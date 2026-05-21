package provider

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/michelangelomo/external-dns-desec-provider/internal/config"
	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/plan"
)

func TestRateLimitTracker_RecordsRetryAfter(t *testing.T) {
	now := time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC)
	tr := &rateLimitTracker{now: func() time.Time { return now }}

	tr.record(5 * time.Second)

	if got := tr.wait(); got != 5*time.Second {
		t.Errorf("wait() = %s, want 5s", got)
	}
}

func TestRateLimitTracker_AllowsAfterExpiry(t *testing.T) {
	cur := time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC)
	tr := &rateLimitTracker{now: func() time.Time { return cur }}

	tr.record(5 * time.Second)
	cur = cur.Add(6 * time.Second)

	if got := tr.wait(); got != 0 {
		t.Errorf("wait() = %s, want 0", got)
	}
}

func TestRateLimitTracker_DoesNotShrinkWindow(t *testing.T) {
	cur := time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC)
	tr := &rateLimitTracker{now: func() time.Time { return cur }}

	tr.record(60 * time.Second)
	tr.record(5 * time.Second) // a shorter retry-after must not shrink the window

	if got := tr.wait(); got != 60*time.Second {
		t.Errorf("wait() = %s, want 60s", got)
	}
}

func TestRateLimitTracker_IgnoresNonPositive(t *testing.T) {
	cur := time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC)
	tr := &rateLimitTracker{now: func() time.Time { return cur }}

	tr.record(0)
	tr.record(-5 * time.Second)

	if got := tr.wait(); got != 0 {
		t.Errorf("wait() = %s, want 0", got)
	}
}

func TestParseRetryAfter_Seconds(t *testing.T) {
	d, ok := parseRetryAfter("120", time.Now())
	if !ok || d != 120*time.Second {
		t.Errorf("parseRetryAfter(\"120\") = (%s, %v), want (2m, true)", d, ok)
	}
}

func TestParseRetryAfter_HTTPDate(t *testing.T) {
	now := time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC)
	target := now.Add(90 * time.Second)
	value := target.Format(http.TimeFormat)

	d, ok := parseRetryAfter(value, now)
	if !ok {
		t.Fatalf("parseRetryAfter(%q) returned ok=false", value)
	}
	if d < 89*time.Second || d > 91*time.Second {
		t.Errorf("parseRetryAfter date duration = %s, want ~90s", d)
	}
}

func TestParseRetryAfter_Invalid(t *testing.T) {
	tests := []string{"", "garbage", "not-a-number"}
	for _, v := range tests {
		if _, ok := parseRetryAfter(v, time.Now()); ok {
			t.Errorf("parseRetryAfter(%q) returned ok=true, want false", v)
		}
	}
}

func TestRateLimitTransport_CapturesRetryAfter(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	tracker := newRateLimitTracker()
	client := &http.Client{
		Transport: &rateLimitTransport{inner: http.DefaultTransport, tracker: tracker},
	}

	req, _ := http.NewRequest(http.MethodGet, server.URL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	_ = resp.Body.Close()

	if requests != 1 {
		t.Errorf("expected 1 request, got %d", requests)
	}
	if d := tracker.wait(); d < 59*time.Second || d > 61*time.Second {
		t.Errorf("tracker.wait() = %s, want ~60s", d)
	}
}

func TestRateLimitTransport_IgnoresNon429(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "60") // present but irrelevant on 200
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	tracker := newRateLimitTracker()
	client := &http.Client{
		Transport: &rateLimitTransport{inner: http.DefaultTransport, tracker: tracker},
	}

	req, _ := http.NewRequest(http.MethodGet, server.URL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	_ = resp.Body.Close()

	if d := tracker.wait(); d != 0 {
		t.Errorf("tracker.wait() = %s after 200 OK, want 0", d)
	}
}

func TestApplyChanges_ShortCircuitsDuringThrottle(t *testing.T) {
	cfg := config.Config{
		APIToken:      "test-token",
		DomainFilters: []string{"example.com"},
		DefaultTTL:    3600,
	}
	client, err := CreateDesecClient(cfg)
	if err != nil {
		t.Fatalf("CreateDesecClient: %v", err)
	}

	client.rateLimit.record(10 * time.Minute)

	err = client.ApplyChanges(plan.Changes{
		Create: []*endpoint.Endpoint{
			{
				DNSName:    "x.example.com",
				RecordType: "A",
				Targets:    endpoint.Targets{"192.0.2.1"},
				RecordTTL:  3600,
			},
		},
	})

	if err == nil {
		t.Fatal("expected RateLimitError, got nil")
	}
	var rle *RateLimitError
	if !errors.As(err, &rle) {
		t.Fatalf("expected *RateLimitError, got %T: %v", err, err)
	}
	if rle.RetryAfter < 9*time.Minute {
		t.Errorf("RetryAfter = %s, want at least 9m", rle.RetryAfter)
	}
}
