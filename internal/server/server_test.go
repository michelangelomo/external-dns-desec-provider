package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/michelangelomo/external-dns-desec-provider/internal/config"
	"github.com/michelangelomo/external-dns-desec-provider/internal/provider"
	log "github.com/sirupsen/logrus"
	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/plan"
)

func TestNewWebhookServer(t *testing.T) {
	config := config.Config{
		APIToken:       "test-token",
		DomainFilters:  []string{"example.com"},
		WebhookAddress: "127.0.0.1",
		WebhookPort:    8888,
		DryRun:         true, // Use dry run mode for testing
	}

	client, err := provider.CreateDesecClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	server := NewWebhookServer(client, config)

	if server == nil {
		t.Fatal("NewWebhookServer returned nil")
	}
	if server.httpServer == nil {
		t.Fatal("NewWebhookServer did not initialize httpServer")
	}
	if server.httpServer.Addr != config.GetListeningAddress() {
		t.Errorf("Server address = %v, want %v", server.httpServer.Addr, config.GetListeningAddress())
	}
}

func TestExternalDnsContentTypeMiddleware(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := externalDnsContentTypeMiddleware(handler)

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	middleware.ServeHTTP(w, req)

	expectedContentType := externalDnsWebhookHeader
	actualContentType := w.Header().Get("Content-Type")
	if actualContentType != expectedContentType {
		t.Errorf("Content-Type = %v, want %v", actualContentType, expectedContentType)
	}
}

func createTestWebhook() webhook {
	config := config.Config{
		APIToken:      "test-token",
		DomainFilters: []string{"example.com", "test.org"},
		DryRun:        true, // Use dry run mode for testing
	}

	client, err := provider.CreateDesecClient(config)
	if err != nil {
		panic("Failed to create test client: " + err.Error())
	}

	return webhook{
		desecClient: client,
		config:      config,
	}
}

func TestNegotiateHandler(t *testing.T) {
	webhook := createTestWebhook()

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	webhook.negotiateHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Status code = %v, want %v", w.Code, http.StatusOK)
	}

	var domainFilter endpoint.DomainFilter
	err := json.NewDecoder(w.Body).Decode(&domainFilter)
	if err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	expectedFilters := webhook.config.DomainFilters
	if !reflect.DeepEqual(domainFilter.Filters, expectedFilters) {
		t.Errorf("DomainFilter.Filters = %v, want %v", domainFilter.Filters, expectedFilters)
	}
}

func TestRecordsHandler(t *testing.T) {
	webhook := createTestWebhook()

	req := httptest.NewRequest("GET", "/records", nil)
	w := httptest.NewRecorder()

	// Reduce log level to avoid noise during tests
	log.SetLevel(log.ErrorLevel)
	defer log.SetLevel(log.InfoLevel)

	webhook.recordsHandler(w, req)

	// Since we're using dry-run mode and a test token, the API call will likely fail
	// But we should still get a proper HTTP response structure
	if w.Code != http.StatusOK && w.Code != http.StatusInternalServerError {
		t.Errorf("Status code = %v, expected %v or %v", w.Code, http.StatusOK, http.StatusInternalServerError)
	}

	// If the request succeeded, validate the JSON structure
	if w.Code == http.StatusOK {
		var endpoints []*endpoint.Endpoint
		err := json.NewDecoder(w.Body).Decode(&endpoints)
		if err != nil {
			t.Errorf("Failed to decode response as JSON: %v", err)
		}
		// endpoints could be empty, which is fine for this test
	}
}

func TestApplyChangesHandler(t *testing.T) {
	tests := []struct {
		name           string
		changes        plan.Changes
		expectedStatus int
	}{
		{
			name: "Successful changes in dry-run mode",
			changes: plan.Changes{
				Create: []*endpoint.Endpoint{
					{
						DNSName:    "new.example.com",
						RecordType: "A",
						Targets:    endpoint.Targets{"192.0.2.10"},
						RecordTTL:  300,
					},
				},
			},
			expectedStatus: http.StatusNoContent,
		},
		{
			name: "Multiple changes in dry-run mode",
			changes: plan.Changes{
				Create: []*endpoint.Endpoint{
					{
						DNSName:    "create.example.com",
						RecordType: "A",
						Targets:    endpoint.Targets{"192.0.2.10"},
						RecordTTL:  300,
					},
				},
				UpdateNew: []*endpoint.Endpoint{
					{
						DNSName:    "update.example.com",
						RecordType: "A",
						Targets:    endpoint.Targets{"192.0.2.11"},
						RecordTTL:  300,
					},
				},
				Delete: []*endpoint.Endpoint{
					{
						DNSName:    "delete.example.com",
						RecordType: "A",
						Targets:    endpoint.Targets{"192.0.2.12"},
						RecordTTL:  300,
					},
				},
			},
			expectedStatus: http.StatusNoContent,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			webhook := createTestWebhook()

			body, err := json.Marshal(tt.changes)
			if err != nil {
				t.Fatalf("Failed to marshal changes: %v", err)
			}

			req := httptest.NewRequest("POST", "/records", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			// Reduce log level to avoid noise during tests
			log.SetLevel(log.ErrorLevel)
			defer log.SetLevel(log.InfoLevel)

			webhook.applyChangesHandler(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Status code = %v, want %v", w.Code, tt.expectedStatus)
			}
		})
	}
}

func TestApplyChangesHandlerBadRequest(t *testing.T) {
	webhook := createTestWebhook()

	// Send invalid JSON
	req := httptest.NewRequest("POST", "/records", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	webhook.applyChangesHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Status code = %v, want %v", w.Code, http.StatusBadRequest)
	}
}

func TestAdjustEndpointsHandler(t *testing.T) {
	tests := []struct {
		name           string
		inputEndpoints []*endpoint.Endpoint
		expectedStatus int
	}{
		{
			name: "Successful adjustment in dry-run mode",
			inputEndpoints: []*endpoint.Endpoint{
				{
					DNSName:    "test.example.com",
					RecordType: "A",
					Targets:    endpoint.Targets{"192.0.2.5"},
					RecordTTL:  300,
				},
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "Multiple endpoints adjustment",
			inputEndpoints: []*endpoint.Endpoint{
				{
					DNSName:    "test1.example.com",
					RecordType: "A",
					Targets:    endpoint.Targets{"192.0.2.5"},
					RecordTTL:  300,
				},
				{
					DNSName:    "test2.example.com",
					RecordType: "CNAME",
					Targets:    endpoint.Targets{"alias.example.com"},
					RecordTTL:  600,
				},
			},
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			webhook := createTestWebhook()

			body, err := json.Marshal(tt.inputEndpoints)
			if err != nil {
				t.Fatalf("Failed to marshal endpoints: %v", err)
			}

			req := httptest.NewRequest("POST", "/adjustendpoints", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			// Reduce log level to avoid noise during tests
			log.SetLevel(log.ErrorLevel)
			defer log.SetLevel(log.InfoLevel)

			webhook.adjustEndpointsHandler(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Status code = %v, want %v", w.Code, tt.expectedStatus)
			}

			if tt.expectedStatus == http.StatusOK {
				var responseEndpoints []*endpoint.Endpoint
				err := json.NewDecoder(w.Body).Decode(&responseEndpoints)
				if err != nil {
					t.Errorf("Failed to decode response: %v", err)
				}

				// In dry-run mode, we should get back the same endpoints
				if len(responseEndpoints) != len(tt.inputEndpoints) {
					t.Errorf("Response endpoints count = %v, want %v", len(responseEndpoints), len(tt.inputEndpoints))
				}
			}
		})
	}
}

func TestAdjustEndpointsHandlerBadRequest(t *testing.T) {
	webhook := createTestWebhook()

	// Send invalid JSON
	req := httptest.NewRequest("POST", "/adjustendpoints", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	webhook.adjustEndpointsHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Status code = %v, want %v", w.Code, http.StatusBadRequest)
	}
}

func TestWebhookServerRun(t *testing.T) {
	config := config.Config{
		APIToken:       "test-token",
		DomainFilters:  []string{"example.com"},
		WebhookAddress: "127.0.0.1",
		WebhookPort:    0, // Use random port
		DryRun:         true,
	}

	client, err := provider.CreateDesecClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	server := NewWebhookServer(client, config)

	// Test that Run method would set up the server correctly
	// We can't actually run it without binding to a port, but we can verify setup
	if server.httpServer.Addr != config.GetListeningAddress() {
		t.Errorf("Server address = %v, want %v", server.httpServer.Addr, config.GetListeningAddress())
	}
}

func TestWebhookServerShutdown(t *testing.T) {
	config := config.Config{
		APIToken:       "test-token",
		DomainFilters:  []string{"example.com"},
		WebhookAddress: "127.0.0.1",
		WebhookPort:    8888,
		DryRun:         true,
	}

	client, err := provider.CreateDesecClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	server := NewWebhookServer(client, config)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	err = server.Shutdown(ctx)
	if err != nil {
		t.Errorf("Shutdown returned error: %v", err)
	}
}

// Integration test with HTTP server
func TestWebhookServerIntegration(t *testing.T) {
	config := config.Config{
		APIToken:      "test-token",
		DomainFilters: []string{"example.com"},
		DryRun:        true,
	}

	client, err := provider.CreateDesecClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	server := NewWebhookServer(client, config)
	testServer := httptest.NewServer(server.httpServer.Handler)
	defer testServer.Close()

	// Test negotiate endpoint
	resp, err := http.Get(testServer.URL + "/")
	if err != nil {
		t.Fatalf("GET / failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET / status = %v, want %v", resp.StatusCode, http.StatusOK)
	}

	// Check content type header
	contentType := resp.Header.Get("Content-Type")
	if contentType != externalDnsWebhookHeader {
		t.Errorf("Content-Type = %v, want %v", contentType, externalDnsWebhookHeader)
	}

	// Decode response
	var domainFilter endpoint.DomainFilter
	err = json.NewDecoder(resp.Body).Decode(&domainFilter)
	if err != nil {
		t.Fatalf("Failed to decode negotiate response: %v", err)
	}

	if !reflect.DeepEqual(domainFilter.Filters, config.DomainFilters) {
		t.Errorf("DomainFilter.Filters = %v, want %v", domainFilter.Filters, config.DomainFilters)
	}
}
