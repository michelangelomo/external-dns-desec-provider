package server

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

func TestRealIP(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string]string
		remoteIP string
		expected string
	}{
		{
			name:     "Direct connection",
			headers:  map[string]string{},
			remoteIP: "192.168.1.1:12345",
			expected: "192.168.1.1",
		},
		{
			name: "X-Forwarded-For single IP",
			headers: map[string]string{
				"X-Forwarded-For": "203.0.113.1",
			},
			remoteIP: "192.168.1.1:12345",
			expected: "203.0.113.1",
		},
		{
			name: "X-Forwarded-For multiple IPs",
			headers: map[string]string{
				"X-Forwarded-For": "203.0.113.1, 198.51.100.1, 192.168.1.1",
			},
			remoteIP: "192.168.1.1:12345",
			expected: "203.0.113.1",
		},
		{
			name: "X-Real-IP",
			headers: map[string]string{
				"X-Real-IP": "203.0.113.2",
			},
			remoteIP: "192.168.1.1:12345",
			expected: "203.0.113.2",
		},
		{
			name: "X-Forwarded-For takes precedence over X-Real-IP",
			headers: map[string]string{
				"X-Forwarded-For": "203.0.113.1",
				"X-Real-IP":       "203.0.113.2",
			},
			remoteIP: "192.168.1.1:12345",
			expected: "203.0.113.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = tt.remoteIP

			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			result := realIP(req)
			if result != tt.expected {
				t.Errorf("realIP() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestNewLogger(t *testing.T) {
	tests := []struct {
		name string
		opts []LogOptions
	}{
		{
			name: "Default options",
			opts: []LogOptions{},
		},
		{
			name: "Custom options",
			opts: []LogOptions{{
				Formatter:      &logrus.JSONFormatter{},
				EnableStarting: true,
			}},
		},
		{
			name: "Enable starting messages",
			opts: []LogOptions{{
				EnableStarting: true,
			}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := NewLogger(tt.opts...)
			if logger == nil {
				t.Fatal("NewLogger returned nil")
			}
			if logger.logger == nil {
				t.Fatal("NewLogger did not initialize logger")
			}
			if logger.clock == nil {
				t.Fatal("NewLogger did not initialize clock")
			}

			if len(tt.opts) > 0 {
				if logger.enableStarting != tt.opts[0].EnableStarting {
					t.Errorf("enableStarting = %v, want %v", logger.enableStarting, tt.opts[0].EnableStarting)
				}
			}
		})
	}
}

func TestLoggingResponseWriter(t *testing.T) {
	w := httptest.NewRecorder()
	lw := newLoggingResponseWriter(w)

	// Test default status code
	if lw.statusCode != http.StatusOK {
		t.Errorf("Default status code = %v, want %v", lw.statusCode, http.StatusOK)
	}

	// Test WriteHeader
	lw.WriteHeader(http.StatusNotFound)
	if lw.statusCode != http.StatusNotFound {
		t.Errorf("Status code after WriteHeader = %v, want %v", lw.statusCode, http.StatusNotFound)
	}

	// Test Write
	data := []byte("test data")
	n, err := lw.Write(data)
	if err != nil {
		t.Errorf("Write returned error: %v", err)
	}
	if n != len(data) {
		t.Errorf("Write returned %v bytes, want %v", n, len(data))
	}
	if w.Body.String() != string(data) {
		t.Errorf("Written data = %v, want %v", w.Body.String(), string(data))
	}
}

func TestLoggingMiddleware(t *testing.T) {
	var logBuffer bytes.Buffer

	logger := NewLogger(LogOptions{
		Formatter: &logrus.TextFormatter{
			DisableTimestamp: true,
			DisableColors:    true,
		},
		EnableStarting: false,
	})
	logger.logger.SetOutput(&logBuffer)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	middleware := logger.Middleware(handler)

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Request-Id", "test-request-id")
	req.RemoteAddr = "192.168.1.1:12345"

	w := httptest.NewRecorder()
	middleware.ServeHTTP(w, req)

	// Check response
	if w.Code != http.StatusOK {
		t.Errorf("Response code = %v, want %v", w.Code, http.StatusOK)
	}
	if w.Body.String() != "OK" {
		t.Errorf("Response body = %v, want %v", w.Body.String(), "OK")
	}

	// Check logs
	logOutput := logBuffer.String()
	if !strings.Contains(logOutput, "completed handling request") {
		t.Error("Log should contain 'completed handling request'")
	}
	if !strings.Contains(logOutput, "status=200") {
		t.Error("Log should contain status=200")
	}
	if !strings.Contains(logOutput, "requestId=test-request-id") {
		t.Error("Log should contain request ID")
	}
	if !strings.Contains(logOutput, "remoteAddr=192.168.1.1") {
		t.Error("Log should contain remote address")
	}
}

func TestLoggingMiddlewareWithStarting(t *testing.T) {
	var logBuffer bytes.Buffer

	logger := NewLogger(LogOptions{
		Formatter: &logrus.TextFormatter{
			DisableTimestamp: true,
			DisableColors:    true,
		},
		EnableStarting: true,
	})
	logger.logger.SetOutput(&logBuffer)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("Created"))
	})

	middleware := logger.Middleware(handler)

	req := httptest.NewRequest("POST", "/create", nil)
	w := httptest.NewRecorder()
	middleware.ServeHTTP(w, req)

	// Check logs contain both starting and completion messages
	logOutput := logBuffer.String()
	if !strings.Contains(logOutput, "started handling request") {
		t.Error("Log should contain 'started handling request'")
	}
	if !strings.Contains(logOutput, "completed handling request") {
		t.Error("Log should contain 'completed handling request'")
	}
	if !strings.Contains(logOutput, "method=POST") {
		t.Error("Log should contain method=POST")
	}
	if !strings.Contains(logOutput, "request=/create") {
		t.Error("Log should contain request path")
	}
	if !strings.Contains(logOutput, "status=201") {
		t.Error("Log should contain status=201")
	}
}

// Test the timer interface
type mockTimer struct {
	now   time.Time
	since time.Duration
}

func (m *mockTimer) Now() time.Time {
	return m.now
}

func (m *mockTimer) Since(time.Time) time.Duration {
	return m.since
}

func TestLoggingMiddlewareWithMockTimer(t *testing.T) {
	var logBuffer bytes.Buffer

	logger := NewLogger()
	logger.logger.SetOutput(&logBuffer)
	logger.logger.SetFormatter(&logrus.TextFormatter{
		DisableTimestamp: true,
		DisableColors:    true,
	})

	// Use mock timer to control timing
	mockTimer := &mockTimer{
		now:   time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
		since: 100 * time.Millisecond,
	}
	logger.clock = mockTimer

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := logger.Middleware(handler)

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	middleware.ServeHTTP(w, req)

	logOutput := logBuffer.String()
	if !strings.Contains(logOutput, "took=100ms") {
		t.Errorf("Log should contain took=100ms, got: %s", logOutput)
	}
}

func TestRealClock(t *testing.T) {
	clock := &realClock{}

	now1 := clock.Now()
	time.Sleep(1 * time.Millisecond)
	now2 := clock.Now()

	if !now2.After(now1) {
		t.Error("Second Now() call should return later time")
	}

	since := clock.Since(now1)
	if since <= 0 {
		t.Error("Since should return positive duration")
	}
}
