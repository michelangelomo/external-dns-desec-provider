package provider

import (
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// RateLimitError is returned when a deSEC API call is short-circuited because
// the client is still inside a throttle window observed from a prior 429
// response. Returning this instead of hitting the API prevents the daily quota
// from being burned while external-dns keeps retrying.
type RateLimitError struct {
	RetryAfter time.Duration
}

func (e *RateLimitError) Error() string {
	return fmt.Sprintf("deSEC rate limit active, retry after %s", e.RetryAfter)
}

// rateLimitTracker remembers the next time the client should attempt to call
// the deSEC API, derived from Retry-After headers seen on 429 responses.
type rateLimitTracker struct {
	mu            sync.Mutex
	nextAllowedAt time.Time
	now           func() time.Time
}

func newRateLimitTracker() *rateLimitTracker {
	return &rateLimitTracker{now: time.Now}
}

// record extends the throttle window. A shorter delay than the current
// deadline is ignored so a later 429 with a smaller Retry-After can't shorten
// a longer window already in effect.
func (t *rateLimitTracker) record(d time.Duration) {
	if d <= 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	deadline := t.now().Add(d)
	if deadline.After(t.nextAllowedAt) {
		t.nextAllowedAt = deadline
	}
}

// wait returns the remaining throttle duration; 0 means the client may proceed.
func (t *rateLimitTracker) wait() time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	remaining := t.nextAllowedAt.Sub(t.now())
	if remaining < 0 {
		return 0
	}
	return remaining
}

// rateLimitTransport is an http.RoundTripper that records Retry-After from any
// 429 Too Many Requests responses observed on the wire, including ones
// retryablehttp will subsequently retry.
type rateLimitTransport struct {
	inner   http.RoundTripper
	tracker *rateLimitTracker
}

func (rt *rateLimitTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := rt.inner.RoundTrip(req)
	if err != nil || resp == nil {
		return resp, err
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		if d, ok := parseRetryAfter(resp.Header.Get("Retry-After"), rt.tracker.now()); ok {
			rt.tracker.record(d)
		}
	}
	return resp, nil
}

// parseRetryAfter parses an HTTP Retry-After header value, which RFC 7231
// defines as either delta-seconds or an HTTP-date, relative to `now`.
func parseRetryAfter(value string, now time.Time) (time.Duration, bool) {
	if value == "" {
		return 0, false
	}
	if secs, err := strconv.Atoi(value); err == nil {
		return time.Duration(secs) * time.Second, true
	}
	if t, err := http.ParseTime(value); err == nil {
		return t.Sub(now), true
	}
	return 0, false
}
