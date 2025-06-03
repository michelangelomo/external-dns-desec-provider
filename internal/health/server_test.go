package health

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/michelangelomo/external-dns-desec-provider/internal/config"
)

func TestHealthzHandler(t *testing.T) {
	req := httptest.NewRequest("GET", "/healthz", nil)
	w := httptest.NewRecorder()

	healthzHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("healthzHandler returned wrong status code: got %v want %v", w.Code, http.StatusOK)
	}

	expected := "ok"
	if w.Body.String() != expected {
		t.Errorf("healthzHandler returned wrong body: got %v want %v", w.Body.String(), expected)
	}
}

func TestReadyzHandler(t *testing.T) {
	req := httptest.NewRequest("GET", "/readyz", nil)
	w := httptest.NewRecorder()

	readyzHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("readyzHandler returned wrong status code: got %v want %v", w.Code, http.StatusOK)
	}

	expected := "ok"
	if w.Body.String() != expected {
		t.Errorf("readyzHandler returned wrong body: got %v want %v", w.Body.String(), expected)
	}
}

func TestNewHealthServer(t *testing.T) {
	server := NewHealthServer()

	if server == nil {
		t.Fatal("NewHealthServer returned nil")
	}

	if server.httpServer == nil {
		t.Fatal("NewHealthServer did not initialize httpServer")
	}

	if server.httpServer.Handler == nil {
		t.Fatal("NewHealthServer did not initialize HTTP handler")
	}
}

func TestHealthServerEndpoints(t *testing.T) {
	server := NewHealthServer()
	testServer := httptest.NewServer(server.httpServer.Handler)
	defer testServer.Close()

	tests := []struct {
		name     string
		endpoint string
		method   string
		wantCode int
		wantBody string
	}{
		{
			name:     "healthz endpoint",
			endpoint: "/healthz",
			method:   "GET",
			wantCode: http.StatusOK,
			wantBody: "ok",
		},
		{
			name:     "readyz endpoint",
			endpoint: "/readyz",
			method:   "GET",
			wantCode: http.StatusOK,
			wantBody: "ok",
		},
		{
			name:     "non-existent endpoint",
			endpoint: "/nonexistent",
			method:   "GET",
			wantCode: http.StatusNotFound,
			wantBody: "",
		},
		{
			name:     "wrong method on healthz",
			endpoint: "/healthz",
			method:   "POST",
			wantCode: http.StatusMethodNotAllowed,
			wantBody: "",
		},
		{
			name:     "wrong method on readyz",
			endpoint: "/readyz",
			method:   "POST",
			wantCode: http.StatusMethodNotAllowed,
			wantBody: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(tt.method, testServer.URL+tt.endpoint, nil)
			if err != nil {
				t.Fatal(err)
			}

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close() //nolint:all

			if resp.StatusCode != tt.wantCode {
				t.Errorf("Status code = %v, want %v", resp.StatusCode, tt.wantCode)
			}

			if tt.wantBody != "" {
				body := make([]byte, len(tt.wantBody))
				_, _ = resp.Body.Read(body)
				if string(body) != tt.wantBody {
					t.Errorf("Body = %v, want %v", string(body), tt.wantBody)
				}
			}
		})
	}
}

func TestHealthServerRun(t *testing.T) {
	server := NewHealthServer()
	config := config.Config{
		HealthAddress: "127.0.0.1",
		HealthPort:    0, // Use random port
	}

	// Test that Run method sets the address correctly
	go func() {
		_ = server.Run(config)
	}()

	// Give the server a moment to start
	time.Sleep(10 * time.Millisecond)

	expectedAddr := config.GetHealthListeningAddress()
	if server.httpServer.Addr != expectedAddr {
		t.Errorf("Server address = %v, want %v", server.httpServer.Addr, expectedAddr)
	}

	// Clean shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	_ = server.Shutdown(ctx)
}

func TestHealthServerShutdown(t *testing.T) {
	server := NewHealthServer()

	// Test shutdown when server is nil (should not panic)
	server.httpServer = nil
	err := server.Shutdown(context.Background())
	if err != nil {
		t.Errorf("Shutdown with nil server returned error: %v", err)
	}

	// Test normal shutdown
	server = NewHealthServer()
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	err = server.Shutdown(ctx)
	if err != nil {
		t.Errorf("Shutdown returned error: %v", err)
	}
}
