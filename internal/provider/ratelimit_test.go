package provider

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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

// TestRateLimitTransport_ClampsRetryAfterHeader pins the fix for the ~12.5h
// silent sleep: a large Retry-After must be recorded verbatim in the tracker
// (so the next call short-circuits for the real window) but clamped in the
// response header the deSEC retry client sees, so a single retry can never
// sleep for hours.
func TestRateLimitTransport_ClampsRetryAfterHeader(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "45000") // deSEC daily-quota style value
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"detail":"Request was throttled. Expected available in 45000 seconds."}`))
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
	defer func() { _ = resp.Body.Close() }()

	if got := resp.Header.Get("Retry-After"); got != "30" {
		t.Errorf("clamped Retry-After header = %q, want \"30\"", got)
	}
	if d := tracker.wait(); d < 44900*time.Second {
		t.Errorf("tracker.wait() = %s, want the full ~45000s window recorded", d)
	}
	// Body must survive the throttle-detail peek so the caller can still read it.
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "throttled") {
		t.Errorf("response body was consumed by detail peek: %q", body)
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

func TestGetEndpoints_ShortCircuitsDuringThrottle(t *testing.T) {
	cfg := config.Config{
		APIToken:      "test-token",
		DomainFilters: []string{"example.com"},
		DefaultTTL:    3600,
	}
	client, err := CreateDesecClient(cfg)
	if err != nil {
		t.Fatalf("CreateDesecClient: %v", err)
	}

	// Point at a server that fails the test if it is ever reached: an open
	// throttle window must be answered from the tracker without a network call.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("deSEC must not be called while throttle window is open")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	client.client.BaseURL = srv.URL + "/"

	client.rateLimit.record(10 * time.Minute)

	_, err = client.GetEndpoints(context.Background(), "example.com")
	var rle *RateLimitError
	if !errors.As(err, &rle) {
		t.Fatalf("expected *RateLimitError, got %T: %v", err, err)
	}
	if rle.RetryAfter < 9*time.Minute {
		t.Errorf("RetryAfter = %s, want at least 9m", rle.RetryAfter)
	}
}

func TestSlidingWindow_ReserveAndExpire(t *testing.T) {
	now := time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC)
	w := &slidingWindow{windowLimit: windowLimit{limit: 2, window: time.Second}}

	if _, ok := w.reserve(now); !ok {
		t.Fatal("first reserve must succeed")
	}
	if _, ok := w.reserve(now); !ok {
		t.Fatal("second reserve must succeed")
	}
	wait, ok := w.reserve(now)
	if ok {
		t.Fatal("third reserve must be refused while window is full")
	}
	if wait <= 0 || wait > time.Second {
		t.Errorf("wait = %s, want a positive sub-second value", wait)
	}
	// After the window elapses the oldest grant ages out.
	if _, ok := w.reserve(now.Add(time.Second + time.Millisecond)); !ok {
		t.Error("reserve must succeed once the window has elapsed")
	}
}

// A read past the dns_api_cheap per-second limit must be told to sleep (a
// sub-minute window), not short-circuited.
func TestProactiveLimiter_ReadBlocksOnPerSecond(t *testing.T) {
	now := time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC)
	p := newProactiveLimiter(func() time.Time { return now })

	for i := 0; i < 10; i++ { // exhaust the 10/s cheap window
		if sleep, short := p.reserve(false, "example.com"); sleep != 0 || short != 0 {
			t.Fatalf("read %d unexpectedly limited: sleep=%s short=%s", i, sleep, short)
		}
	}
	sleep, short := p.reserve(false, "example.com")
	if short != 0 {
		t.Errorf("per-second read limit must sleep, not short-circuit (short=%s)", short)
	}
	if sleep <= 0 || sleep > time.Second {
		t.Errorf("sleep = %s, want a positive sub-second value", sleep)
	}
}

// A write past the per-domain expensive per-hour limit must short-circuit (an
// hour window must never be slept on), surfaced to the caller as a wait.
func TestProactiveLimiter_WriteShortCircuitsOnPerHour(t *testing.T) {
	now := time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC)
	p := newProactiveLimiter(func() time.Time { return now })

	// Fill the per-hour window (100 grants) spaced 35s apart so they all stay
	// within the hour but the 2/s and 15/min windows never trip first,
	// isolating the hour window as the limiter that fires.
	for i := 0; i < 100; i++ {
		if sleep, short := p.reserve(true, "example.com"); sleep != 0 || short != 0 {
			t.Fatalf("write %d unexpectedly limited: sleep=%s short=%s", i, sleep, short)
		}
		now = now.Add(35 * time.Second)
	}
	sleep, short := p.reserve(true, "example.com")
	if sleep != 0 {
		t.Errorf("per-hour write limit must short-circuit, not sleep (sleep=%s)", sleep)
	}
	if short <= 0 {
		t.Errorf("expected a positive short-circuit wait, got %s", short)
	}
}

// The per-domain expensive scope is keyed per domain: exhausting one domain's
// window must not throttle another.
func TestProactiveLimiter_ExpensiveIsPerDomain(t *testing.T) {
	now := time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC)
	p := newProactiveLimiter(func() time.Time { return now })

	for i := 0; i < 2; i++ { // exhaust the 2/s window for a.example
		if sleep, short := p.reserve(true, "a.example"); sleep != 0 || short != 0 {
			t.Fatalf("write %d to a.example unexpectedly limited", i)
		}
	}
	if sleep, short := p.reserve(true, "b.example"); sleep != 0 || short != 0 {
		t.Errorf("b.example must not be throttled by a.example's window: sleep=%s short=%s", sleep, short)
	}
}

// The reactive Retry-After window always wins over the proactive verdict.
func TestApplyProactive_ReactiveWindowWins(t *testing.T) {
	now := time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC)
	tracker := &rateLimitTracker{now: func() time.Time { return now }}
	tracker.record(10 * time.Minute)

	rt := &rateLimitTransport{
		inner:     http.DefaultTransport,
		tracker:   tracker,
		proactive: newProactiveLimiter(func() time.Time { return now }),
	}

	req, _ := http.NewRequest(http.MethodGet, "https://desec.io/api/v1/domains/example.com/rrsets/", nil)
	err := rt.applyProactive(req)
	var rle *RateLimitError
	if !errors.As(err, &rle) {
		t.Fatalf("expected *RateLimitError from the open reactive window, got %T: %v", err, err)
	}
	if rle.RetryAfter < 9*time.Minute {
		t.Errorf("RetryAfter = %s, want the reactive 10m window", rle.RetryAfter)
	}
}

func TestClassifyRRSetRequest(t *testing.T) {
	tests := []struct {
		method     string
		path       string
		wantWrite  bool
		wantDomain string
	}{
		{http.MethodGet, "/api/v1/domains/example.com/rrsets/", false, "example.com"},
		{http.MethodPut, "/api/v1/domains/example.com/rrsets/", true, "example.com"},
		{http.MethodPost, "/api/v1/domains/sub.example.org/rrsets/", true, "sub.example.org"},
		{http.MethodDelete, "/api/v1/domains/example.com/rrsets/www/A/", true, "example.com"},
	}
	for _, tt := range tests {
		req, _ := http.NewRequest(tt.method, "https://desec.io"+tt.path, nil)
		write, domain := classifyRRSetRequest(req)
		if write != tt.wantWrite || domain != tt.wantDomain {
			t.Errorf("classify(%s %s) = (%v, %q), want (%v, %q)", tt.method, tt.path, write, domain, tt.wantWrite, tt.wantDomain)
		}
	}
}

func TestCachedEndpoints_AllOrNothing(t *testing.T) {
	now := time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC)
	client, err := CreateDesecClient(config.Config{
		APIToken:      "test-token",
		DomainFilters: []string{"a.example", "b.example"},
		DefaultTTL:    3600,
	})
	if err != nil {
		t.Fatalf("CreateDesecClient: %v", err)
	}
	client.rateLimit.now = func() time.Time { return now }

	client.cache["a.example"] = cachedEndpoints{
		endpoints: []*endpoint.Endpoint{{DNSName: "x.a.example", RecordType: "A"}},
		fetchedAt: now,
	}

	// b.example was never fetched -> all-or-nothing must refuse.
	if _, ok := client.CachedEndpoints([]string{"a.example", "b.example"}); ok {
		t.Fatal("CachedEndpoints returned ok with a missing domain; must be all-or-nothing")
	}

	client.cache["b.example"] = cachedEndpoints{
		endpoints: []*endpoint.Endpoint{{DNSName: "y.b.example", RecordType: "A"}},
		fetchedAt: now,
	}
	eps, ok := client.CachedEndpoints([]string{"a.example", "b.example"})
	if !ok {
		t.Fatal("CachedEndpoints refused a full, fresh cache")
	}
	if len(eps) != 2 {
		t.Errorf("cached endpoints = %d, want 2", len(eps))
	}
}

func TestCachedEndpoints_RefusesStale(t *testing.T) {
	now := time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC)
	client, err := CreateDesecClient(config.Config{
		APIToken:      "test-token",
		DomainFilters: []string{"a.example"},
		DefaultTTL:    3600,
	})
	if err != nil {
		t.Fatalf("CreateDesecClient: %v", err)
	}
	client.rateLimit.now = func() time.Time { return now }

	client.cache["a.example"] = cachedEndpoints{
		endpoints: []*endpoint.Endpoint{{DNSName: "x.a.example", RecordType: "A"}},
		fetchedAt: now.Add(-maxCacheStaleness - time.Minute),
	}

	if _, ok := client.CachedEndpoints([]string{"a.example"}); ok {
		t.Error("CachedEndpoints served a cache older than maxCacheStaleness")
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

	err = client.ApplyChanges(context.Background(), plan.Changes{
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
