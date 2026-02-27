package desec

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newTestClient(t *testing.T, handler http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(handler)
	client := NewClient("test-token")
	client.baseURL = server.URL
	return client, server
}

func TestGetRecords_Success(t *testing.T) {
	expected := []RRSet{
		{SubName: "www", Type: "A", Records: []string{"192.0.2.1"}, TTL: 3600},
		{SubName: "", Type: "MX", Records: []string{"10 mail.example.com."}, TTL: 3600},
	}

	client, server := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		if r.Header.Get("Authorization") != "Token test-token" {
			t.Errorf("unexpected Authorization header: %s", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(expected)
	})
	defer server.Close()

	result, err := client.GetRecords(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != len(expected) {
		t.Fatalf("expected %d rrsets, got %d", len(expected), len(result))
	}
	for i := range expected {
		if result[i].SubName != expected[i].SubName || result[i].Type != expected[i].Type {
			t.Errorf("rrset %d: expected %+v, got %+v", i, expected[i], result[i])
		}
	}
}

func TestBulkCreateRecords_Success(t *testing.T) {
	input := []RRSet{
		{SubName: "www", Type: "A", Records: []string{"192.0.2.1"}, TTL: 3600},
	}

	client, server := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("unexpected Content-Type: %s", r.Header.Get("Content-Type"))
		}

		var received []RRSet
		json.NewDecoder(r.Body).Decode(&received)

		w.WriteHeader(http.StatusCreated)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(received)
	})
	defer server.Close()

	result, err := client.BulkCreateRecords(context.Background(), "example.com", input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 rrset, got %d", len(result))
	}
	if result[0].SubName != "www" {
		t.Errorf("expected SubName 'www', got '%s'", result[0].SubName)
	}
}

func TestBulkUpdateRecords_Success(t *testing.T) {
	input := []RRSet{
		{SubName: "www", Type: "A", Records: []string{"192.0.2.2"}, TTL: 3600},
	}

	client, server := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("expected PUT, got %s", r.Method)
		}

		var received []RRSet
		json.NewDecoder(r.Body).Decode(&received)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(received)
	})
	defer server.Close()

	result, err := client.BulkUpdateRecords(context.Background(), "example.com", input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 1 || result[0].Records[0] != "192.0.2.2" {
		t.Errorf("unexpected result: %+v", result)
	}
}

func TestRateLimitError(t *testing.T) {
	client, server := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "3600")
		w.WriteHeader(http.StatusTooManyRequests)
	})
	defer server.Close()

	_, err := client.GetRecords(context.Background(), "example.com")
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	rle, ok := err.(*RateLimitError)
	if !ok {
		t.Fatalf("expected *RateLimitError, got %T: %v", err, err)
	}
	if rle.RetryAfter != 3600 {
		t.Errorf("expected RetryAfter 3600, got %d", rle.RetryAfter)
	}
}

func TestRateLimitError_NoRetryAfterHeader(t *testing.T) {
	client, server := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	})
	defer server.Close()

	_, err := client.GetRecords(context.Background(), "example.com")
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	rle, ok := err.(*RateLimitError)
	if !ok {
		t.Fatalf("expected *RateLimitError, got %T: %v", err, err)
	}
	if rle.RetryAfter != 0 {
		t.Errorf("expected RetryAfter 0, got %d", rle.RetryAfter)
	}
}

func TestAPIError_BadRequest(t *testing.T) {
	client, server := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"detail":"invalid data"}`))
	})
	defer server.Close()

	_, err := client.BulkCreateRecords(context.Background(), "example.com", []RRSet{})
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("expected *APIError, got %T: %v", err, err)
	}
	if apiErr.StatusCode != 400 {
		t.Errorf("expected status 400, got %d", apiErr.StatusCode)
	}
	if apiErr.Body != `{"detail":"invalid data"}` {
		t.Errorf("unexpected body: %s", apiErr.Body)
	}
}

func TestAPIError_InternalServerError(t *testing.T) {
	client, server := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal server error"))
	})
	defer server.Close()

	_, err := client.GetRecords(context.Background(), "example.com")
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("expected *APIError, got %T: %v", err, err)
	}
	if apiErr.StatusCode != 500 {
		t.Errorf("expected status 500, got %d", apiErr.StatusCode)
	}
}

func TestBulkDeleteRecords_SetsEmptyRecords(t *testing.T) {
	client, server := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("expected PUT for delete, got %s", r.Method)
		}

		var received []RRSet
		json.NewDecoder(r.Body).Decode(&received)

		for i, rr := range received {
			if len(rr.Records) != 0 {
				t.Errorf("rrset %d: expected empty records, got %v", i, rr.Records)
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(received)
	})
	defer server.Close()

	input := []RRSet{
		{SubName: "www", Type: "A", Records: []string{"192.0.2.1"}, TTL: 3600},
		{SubName: "api", Type: "CNAME", Records: []string{"target.example.com."}, TTL: 3600},
	}

	err := client.BulkDeleteRecords(context.Background(), "example.com", input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRequestURL_Format(t *testing.T) {
	var capturedPath string
	client, server := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]RRSet{})
	})
	defer server.Close()

	client.GetRecords(context.Background(), "example.com")

	expected := "/domains/example.com/rrsets/"
	if capturedPath != expected {
		t.Errorf("expected path %q, got %q", expected, capturedPath)
	}
}
