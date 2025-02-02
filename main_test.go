package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestGetSubnameAndDomain tests various fullName cases.
func TestGetSubnameAndDomain(t *testing.T) {
	tests := []struct {
		fullName        string
		expectedSubname string
		expectedDomain  string
	}{
		{"www.example.com", "www", "example.com"},
		{"example.com", "", "example.com"},
		{"sub.domain.example.com", "sub.domain", "example.com"},
		{"a.b.c.d", "a.b", "c.d"},
		{"local", "", "local"},
	}
	for _, tc := range tests {
		sub, dom := getSubnameAndDomain(tc.fullName)
		if sub != tc.expectedSubname || dom != tc.expectedDomain {
			t.Errorf("For %q, got subname=%q, domain=%q; expected %q, %q",
				tc.fullName, sub, dom, tc.expectedSubname, tc.expectedDomain)
		}
	}
}

// TestProcessChange_Invalid verifies that missing action or record name returns an error.
func TestProcessChange_Invalid(t *testing.T) {
	cfg := Config{APIToken: "dummy"}
	// Missing action.
	change := Change{
		Action: "",
		Record: Record{
			Name:    "www.example.com",
			Type:    "A",
			TTL:     60,
			Targets: []string{"1.2.3.4"},
		},
	}
	resp := processChange(cfg, change)
	if errResp, ok := resp.(ErrorResponse); !ok || errResp.Error != "Invalid change request" {
		t.Errorf("Expected invalid change error, got %+v", resp)
	}

	// Missing record name.
	change = Change{
		Action: "CREATE",
		Record: Record{
			Name:    "",
			Type:    "A",
			TTL:     60,
			Targets: []string{"1.2.3.4"},
		},
	}
	resp = processChange(cfg, change)
	if errResp, ok := resp.(ErrorResponse); !ok || errResp.Error != "Invalid change request" {
		t.Errorf("Expected invalid change error, got %+v", resp)
	}
}

// TestProcessChange_Create uses a test server to simulate a CREATE action.
func TestProcessChange_Create(t *testing.T) {
	// Create an httptest server.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// For the initial GET, return 404 to force creation.
		if r.Method == http.MethodGet {
			http.NotFound(w, r)
			return
		}
		// For POST, check method, URL, and return success.
		if r.Method == http.MethodPost {
			var rr RRSet
			buf := new(bytes.Buffer)
			buf.ReadFrom(r.Body)
			if err := json.Unmarshal(buf.Bytes(), &rr); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			// Simulate success.
			w.WriteHeader(http.StatusOK)
			return
		}
		// Default response.
		w.WriteHeader(http.StatusMethodNotAllowed)
	}))
	defer ts.Close()

	// Override the desecAPIBase variable for testing.
	originalBase := desecAPIBase
	desecAPIBase = ts.URL
	defer func() { desecAPIBase = originalBase }()

	cfg := Config{APIToken: "dummy"}
	change := Change{
		Action: "CREATE",
		Record: Record{
			Name:    "www.example.com",
			Type:    "A",
			TTL:     60,
			Targets: []string{"1.2.3.4"},
		},
	}

	// Set a shorter timeout for tests.
	origTimeout := requestTimeout
	requestTimeout = 2 * time.Second
	defer func() { requestTimeout = origTimeout }()

	resp := processChange(cfg, change)
	if success, ok := resp.(SuccessResponse); !ok || success.Success != true {
		t.Errorf("Expected success response, got %+v", resp)
	}
}
