package provider

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// deSEC applies several throttle scopes; the one that bites the read path is
// the account-wide `user` scope of 2000 requests/day, shared across ALL
// domains and both read and write. When it is exhausted deSEC answers 429 with
// a Retry-After that can be ~12.5h (the remaining seconds of the daily bucket).
// The per-request read scope `dns_api_cheap` (10/s 50/min) is comparatively
// generous and is not the limit we hit in practice.
// https://desec.readthedocs.io/en/latest/rate-limits.html
const userDailyRequestLimit = 2000

// retryAfterCap bounds how long a single retryablehttp attempt may sleep on a
// 429. The deSEC library builds its retry client internally and exposes no
// Backoff hook, so we clamp the Retry-After header the transport hands upward:
// DefaultBackoff sleeps the header value verbatim (not clamped to
// RetryWaitMax), which is how a 429 turned into a silent ~12.5h sleep. The
// unclamped duration is still recorded in the tracker so the next call
// short-circuits for the real window.
const retryAfterCap = 30 * time.Second

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
// the deSEC API, derived from Retry-After headers seen on 429 responses. It
// also counts requests within the current UTC day to warn before the
// account-wide `user` daily quota is exhausted.
type rateLimitTracker struct {
	mu            sync.Mutex
	nextAllowedAt time.Time
	now           func() time.Time

	dayStart  time.Time
	dayCount  int
	warnedDay bool
}

func newRateLimitTracker() *rateLimitTracker {
	return &rateLimitTracker{now: time.Now}
}

// observeRequest counts every request against the daily `user` budget and warns
// once per day when the remaining budget runs low, so the eventual 429 is not
// the first sign that the account is out of quota. Records roll over on the UTC
// day boundary deSEC uses to reset the bucket.
func (t *rateLimitTracker) observeRequest() {
	t.mu.Lock()
	defer t.mu.Unlock()

	day := t.now().UTC().Truncate(24 * time.Hour)
	if day.After(t.dayStart) {
		t.dayStart = day
		t.dayCount = 0
		t.warnedDay = false
	}
	t.dayCount++

	const warnThreshold = userDailyRequestLimit * 9 / 10
	if t.dayCount >= warnThreshold && !t.warnedDay {
		t.warnedDay = true
		log.Warnf("approaching deSEC daily request limit: %d/%d requests today (account-wide, all domains)",
			t.dayCount, userDailyRequestLimit)
	}
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

// deSEC rate-limit scopes exercised by this provider, from
// https://desec.readthedocs.io/en/latest/rate-limits.html. Requests are checked
// against these BEFORE going on the wire, so we avoid the 429 rather than react
// to it. Sub-minute windows are cheap to wait out; the hour/day windows are
// short-circuited to the cache/500 path instead of sleeping for hours.
//
//	dns_api_cheap                 10/s,  50/min                 reads, per user
//	dns_api_per_domain_expensive  2/s, 15/min, 100/h, 300/day   writes, per user PER DOMAIN
//	user                          2000/day                      any request, account-wide
var (
	cheapWindows      = []windowLimit{{10, time.Second}, {50, time.Minute}}
	expensiveWindows  = []windowLimit{{2, time.Second}, {15, time.Minute}, {100, time.Hour}, {300, 24 * time.Hour}}
	userDailyWindow   = []windowLimit{{userDailyRequestLimit, 24 * time.Hour}}
	proactiveSleepCap = 5 * time.Second
)

// windowLimit is a max request count within a sliding time window.
type windowLimit struct {
	limit  int
	window time.Duration
}

// slidingWindow tracks recent grant timestamps within its window and hands out
// slots up to limit. It is the building block of every deSEC scope bucket.
type slidingWindow struct {
	windowLimit
	grants []time.Time
}

// reserve, given the current time, either records a grant and returns (0, true)
// or, if the window is full, returns the wait until the oldest grant expires and
// (_, false). Expired grants are pruned on every call.
func (w *slidingWindow) reserve(now time.Time) (time.Duration, bool) {
	cutoff := now.Add(-w.window)
	kept := w.grants[:0]
	for _, g := range w.grants {
		if g.After(cutoff) {
			kept = append(kept, g)
		}
	}
	w.grants = kept

	if len(w.grants) < w.limit {
		w.grants = append(w.grants, now)
		return 0, true
	}
	// Full: the oldest grant must age out of the window before a slot frees.
	return w.grants[0].Sub(cutoff), false
}

// scopeLimiter guards one deSEC scope key (a fixed scope, or a scope+domain for
// the per-domain expensive bucket) with a sliding window per configured limit.
type scopeLimiter struct {
	mu      sync.Mutex
	windows []*slidingWindow
}

func newScopeLimiter(limits []windowLimit) *scopeLimiter {
	windows := make([]*slidingWindow, len(limits))
	for i, l := range limits {
		windows[i] = &slidingWindow{windowLimit: l}
	}
	return &scopeLimiter{windows: windows}
}

// proactiveLimiter holds the per-scope buckets consulted before a request. The
// per-domain expensive scope is keyed lazily as domains are seen.
type proactiveLimiter struct {
	mu        sync.Mutex
	cheap     *scopeLimiter
	user      *scopeLimiter
	expensive map[string]*scopeLimiter
	now       func() time.Time
}

func newProactiveLimiter(now func() time.Time) *proactiveLimiter {
	return &proactiveLimiter{
		cheap:     newScopeLimiter(cheapWindows),
		user:      newScopeLimiter(userDailyWindow),
		expensive: make(map[string]*scopeLimiter),
		now:       now,
	}
}

func (p *proactiveLimiter) expensiveFor(domain string) *scopeLimiter {
	p.mu.Lock()
	defer p.mu.Unlock()
	sl := p.expensive[domain]
	if sl == nil {
		sl = newScopeLimiter(expensiveWindows)
		p.expensive[domain] = sl
	}
	return sl
}

// reserve checks the buckets for a read or write request against domain. It
// returns the duration to sleep before proceeding (bounded by the caller) for
// sub-minute windows, and shortCircuit=true with a *RateLimitError-worthy wait
// when an hour/day window is full -- those must not be slept on. A slot is
// reserved in every consulted window only when the whole request is admissible.
func (p *proactiveLimiter) reserve(write bool, domain string) (sleep time.Duration, shortCircuit time.Duration) {
	scopes := []*scopeLimiter{p.user}
	if write {
		scopes = append(scopes, p.expensiveFor(domain))
	} else {
		scopes = append(scopes, p.cheap)
	}

	now := p.now()

	// First pass: probe without committing. If any hour/day window is full,
	// short-circuit; otherwise take the longest sub-minute wait to sleep out.
	// Probing avoids reserving slots we'd then abandon on a short-circuit.
	var maxSleep, maxShort time.Duration
	for _, sc := range scopes {
		sc.mu.Lock()
		for _, w := range sc.windows {
			cutoff := now.Add(-w.window)
			active := 0
			var oldest time.Time
			for _, g := range w.grants {
				if g.After(cutoff) {
					if active == 0 || g.Before(oldest) {
						oldest = g
					}
					active++
				}
			}
			if active < w.limit {
				continue
			}
			wait := oldest.Sub(cutoff)
			if w.window <= time.Minute {
				if wait > maxSleep {
					maxSleep = wait
				}
			} else if wait > maxShort {
				maxShort = wait
			}
		}
		sc.mu.Unlock()
	}
	if maxShort > 0 {
		return 0, maxShort
	}
	if maxSleep > 0 {
		return maxSleep, 0
	}

	// Admissible now: commit a grant in every window of every consulted scope.
	for _, sc := range scopes {
		sc.mu.Lock()
		for _, w := range sc.windows {
			_, _ = w.reserve(now)
		}
		sc.mu.Unlock()
	}
	return 0, 0
}

// rateLimitTransport is an http.RoundTripper that proactively throttles against
// deSEC's documented scopes before a request, and reactively records Retry-After
// from any 429 Too Many Requests responses observed on the wire (including ones
// retryablehttp will subsequently retry). The reactive window always wins: a
// recorded Retry-After short-circuits regardless of the proactive buckets.
type rateLimitTransport struct {
	inner     http.RoundTripper
	tracker   *rateLimitTracker
	proactive *proactiveLimiter
}

func (rt *rateLimitTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rt.tracker.observeRequest()

	if rt.proactive != nil {
		if err := rt.applyProactive(req); err != nil {
			return nil, err
		}
	}

	resp, err := rt.inner.RoundTrip(req)
	if err != nil || resp == nil {
		return resp, err
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		retryAfter := resp.Header.Get("Retry-After")
		log.Warnf("deSEC throttled %s %s: HTTP 429, Retry-After=%q, detail=%q",
			req.Method, req.URL.Path, retryAfter, peekThrottleDetail(resp))
		if d, ok := parseRetryAfter(retryAfter, rt.tracker.now()); ok {
			// Record the real window so the next call short-circuits, but clamp
			// the header retryablehttp sees so a single attempt can never sleep
			// for hours if the request context is not cancelled in time.
			rt.tracker.record(d)
			if d > retryAfterCap {
				resp.Header.Set("Retry-After", strconv.Itoa(int(retryAfterCap/time.Second)))
			}
		}
	}
	return resp, nil
}

// applyProactive enforces the proactive scope buckets and the reactive
// Retry-After window before a request goes on the wire. The reactive window
// always wins (max of the two next-allowed times): an hour/day scope or an open
// 429 window short-circuits with a *RateLimitError so the caller falls to the
// cache/500 path; a sub-minute scope is slept out, bounded by proactiveSleepCap
// and honouring the request context.
func (rt *rateLimitTransport) applyProactive(req *http.Request) error {
	write, domain := classifyRRSetRequest(req)

	sleep, shortCircuit := rt.proactive.reserve(write, domain)

	// The reactive window (recorded from a prior 429) always wins.
	if reactive := rt.tracker.wait(); reactive > shortCircuit {
		shortCircuit = reactive
	}
	if shortCircuit > 0 {
		return &RateLimitError{RetryAfter: shortCircuit}
	}

	if sleep > 0 {
		if sleep > proactiveSleepCap {
			sleep = proactiveSleepCap
		}
		t := time.NewTimer(sleep)
		defer t.Stop()
		select {
		case <-t.C:
		case <-req.Context().Done():
			return req.Context().Err()
		}
	}
	return nil
}

// classifyRRSetRequest inspects a deSEC rrsets request and reports whether it is
// a write (mutating method) and the domain it targets. deSEC's URL shape is
// /domains/<domain>/rrsets[/<subname>/<type>], so the segment after "domains"
// is the per-domain key for the expensive write scope.
func classifyRRSetRequest(req *http.Request) (write bool, domain string) {
	switch req.Method {
	case http.MethodPut, http.MethodPost, http.MethodPatch, http.MethodDelete:
		write = true
	}
	parts := strings.Split(strings.Trim(req.URL.Path, "/"), "/")
	for i, p := range parts {
		if p == "domains" && i+1 < len(parts) {
			domain = parts[i+1]
			break
		}
	}
	return write, domain
}

// peekThrottleDetail reads deSEC's JSON throttle body ("Request was throttled.
// Expected available in N seconds.") for logging, then rewinds it so the caller
// can still consume the response.
func peekThrottleDetail(resp *http.Response) string {
	if resp.Body == nil {
		return ""
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 512))
	if err != nil {
		return ""
	}
	rest, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	resp.Body = io.NopCloser(io.MultiReader(bytes.NewReader(body), bytes.NewReader(rest)))
	return string(body)
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
