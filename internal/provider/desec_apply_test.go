package provider

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/michelangelomo/external-dns-desec-provider/internal/config"
	"github.com/nrdcg/desec"
	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/plan"
)

// desecMock is an in-memory stand-in for the deSEC /rrsets/ API that enforces
// the two real constraints exercised by the atomic-bulk-apply fix:
//   - POST /rrsets/ (bulk create) only accepts brand-new rrsets, and
//   - a CNAME may not coexist with any other type at the same subname.
//
// Bulk operations validate the *resulting* zone state and are atomic: either
// all rrsets in the request are applied or none are (matching deSEC's
// documented bulk semantics).
type desecMock struct {
	mu sync.Mutex
	// zone keys an rrset by "subname|type"; value is its records.
	zone map[string][]string
	// requestCount counts mutating bulk requests (POST/PUT/PATCH) served.
	requestCount int
}

func newDesecMock() *desecMock {
	return &desecMock{zone: make(map[string][]string)}
}

func zoneKey(subname, typ string) string { return subname + "|" + typ }

// seed inserts a record directly, bypassing constraint checks.
func (m *desecMock) seed(subname, typ string, records ...string) {
	m.zone[zoneKey(subname, typ)] = records
}

// has reports whether an rrset exists for the given subname/type.
func (m *desecMock) has(subname, typ string) bool {
	_, ok := m.zone[zoneKey(subname, typ)]
	return ok
}

// subnameTypes returns the set of record types present at a subname.
func (m *desecMock) subnameTypes() map[string]map[string]bool {
	out := make(map[string]map[string]bool)
	for k := range m.zone {
		parts := strings.SplitN(k, "|", 2)
		sub, typ := parts[0], parts[1]
		if out[sub] == nil {
			out[sub] = make(map[string]bool)
		}
		out[sub][typ] = true
	}
	return out
}

// desec-shaped 400 body: a JSON array of per-rrset error objects.
func writeDesecError(w http.ResponseWriter, detail string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode([]map[string]any{
		{"non_field_errors": []string{detail}},
	})
}

func (m *desecMock) server(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	// Path: /domains/<domain>/rrsets/
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/rrsets/") {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		var rrsets []desec.RRSet
		if err := json.NewDecoder(r.Body).Decode(&rrsets); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}

		m.mu.Lock()
		defer m.mu.Unlock()

		switch r.Method {
		case http.MethodPost:
			m.requestCount++
			// Create-only: reject if any rrset already exists, then validate
			// the resulting state. Apply atomically.
			next := m.clone()
			for _, rr := range rrsets {
				if m.has(rr.SubName, rr.Type) {
					writeDesecError(w, fmt.Sprintf("RRset %q/%q already exists.", rr.SubName, rr.Type))
					return
				}
				next[zoneKey(rr.SubName, rr.Type)] = rr.Records
			}
			if detail, ok := validateZone(next); !ok {
				writeDesecError(w, detail)
				return
			}
			m.zone = next
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(rrsets)

		case http.MethodPut, http.MethodPatch:
			m.requestCount++
			// Upsert; records:[] deletes. Validate resulting state atomically.
			next := m.clone()
			for _, rr := range rrsets {
				if len(rr.Records) == 0 {
					delete(next, zoneKey(rr.SubName, rr.Type))
					continue
				}
				next[zoneKey(rr.SubName, rr.Type)] = rr.Records
			}
			if detail, ok := validateZone(next); !ok {
				writeDesecError(w, detail)
				return
			}
			m.zone = next
			w.WriteHeader(http.StatusOK)
			out := make([]desec.RRSet, 0)
			for _, rr := range rrsets {
				if len(rr.Records) > 0 {
					out = append(out, rr)
				}
			}
			_ = json.NewEncoder(w).Encode(out)

		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func (m *desecMock) clone() map[string][]string {
	out := make(map[string][]string, len(m.zone))
	for k, v := range m.zone {
		cp := make([]string, len(v))
		copy(cp, v)
		out[k] = cp
	}
	return out
}

// validateZone enforces the deSEC CNAME-coexistence rule against a candidate
// final zone state: a CNAME may not share a subname with any other type.
func validateZone(zone map[string][]string) (string, bool) {
	types := make(map[string]map[string]bool)
	for k := range zone {
		parts := strings.SplitN(k, "|", 2)
		sub, typ := parts[0], parts[1]
		if types[sub] == nil {
			types[sub] = make(map[string]bool)
		}
		types[sub][typ] = true
	}
	for sub, ts := range types {
		if ts["CNAME"] && len(ts) > 1 {
			var other string
			for t := range ts {
				if t != "CNAME" {
					other = t
					break
				}
			}
			return fmt.Sprintf("RRset with conflicting type present at same subname: %s (%s). (No other RRsets are allowed alongside CNAME.)", sub, other), false
		}
	}
	return "", true
}

// newTestClient builds a DesecClient wired to the mock server's base URL.
func newTestClient(t *testing.T, srv *httptest.Server) *DesecClient {
	t.Helper()
	cfg := config.Config{
		APIToken:      "test-token",
		DomainFilters: []string{"example.com"},
		DryRun:        false,
		DefaultTTL:    3600,
	}
	client, err := CreateDesecClient(cfg)
	if err != nil {
		t.Fatalf("CreateDesecClient: %v", err)
	}
	// Point the underlying nrdcg/desec client at the test server.
	client.client.BaseURL = srv.URL + "/"
	return client
}

// Test 1 (constraint pin): a lone bulk-create of a CNAME where an A already
// exists is rejected by the mock with a deSEC-style 400. Documents the rule.
func TestDesecMock_RejectsCNAMEOverExistingA(t *testing.T) {
	m := newDesecMock()
	m.seed("foo", "A", "1.2.3.4")
	srv := m.server(t)
	client := newTestClient(t, srv)

	_, err := client.client.Records.BulkCreate(client.ctx, "example.com", []desec.RRSet{
		{SubName: "foo", Type: "CNAME", Records: []string{"bar.example."}, TTL: 3600},
	})
	if err == nil {
		t.Fatal("expected mock to reject CNAME-over-A bulk create, got nil error")
	}
	if !strings.Contains(err.Error(), "No other RRsets are allowed alongside CNAME") {
		t.Errorf("expected deSEC CNAME-coexistence error, got: %v", err)
	}
	// Zone must be unchanged (atomic reject).
	if m.has("foo", "CNAME") {
		t.Error("CNAME must not have been created after rejection")
	}
	if !m.has("foo", "A") {
		t.Error("pre-existing A must remain after rejection")
	}
}

// Test 2 (repro -> fix): an A->CNAME retype reaches the provider as
// Delete(old A) + Create(new CNAME) at the same subname. Against the current
// code (Create-first POST) the mock 400s. After the fix it must succeed and
// leave only the CNAME.
func TestApplyChanges_RetypeAtoCNAME(t *testing.T) {
	m := newDesecMock()
	m.seed("foo", "A", "1.2.3.4")
	srv := m.server(t)
	client := newTestClient(t, srv)

	changes := plan.Changes{
		Create: []*endpoint.Endpoint{
			{DNSName: "foo.example.com", RecordType: "CNAME", Targets: endpoint.Targets{"bar.example."}, RecordTTL: 3600},
		},
		Delete: []*endpoint.Endpoint{
			{DNSName: "foo.example.com", RecordType: "A", Targets: endpoint.Targets{"1.2.3.4"}, RecordTTL: 3600},
		},
	}

	err := client.ApplyChanges(changes)
	if err != nil {
		t.Fatalf("ApplyChanges(retype A->CNAME) must succeed after the atomic-bulk fix, got: %v", err)
	}

	if m.has("foo", "A") {
		t.Error("old A record must be gone after retype")
	}
	if !m.has("foo", "CNAME") {
		t.Error("new CNAME record must exist after retype")
	}
}

// Test 3 (combine update+create): an UpdateNew plus a separate Create for the
// same domain must be sent as a SINGLE bulk request, and both must land.
func TestApplyChanges_CombinesUpdateAndCreateInOneRequest(t *testing.T) {
	m := newDesecMock()
	m.seed("a", "A", "1.1.1.1")
	srv := m.server(t)
	client := newTestClient(t, srv)

	changes := plan.Changes{
		UpdateNew: []*endpoint.Endpoint{
			{DNSName: "a.example.com", RecordType: "A", Targets: endpoint.Targets{"2.2.2.2"}, RecordTTL: 3600},
		},
		Create: []*endpoint.Endpoint{
			{DNSName: "b.example.com", RecordType: "A", Targets: endpoint.Targets{"3.3.3.3"}, RecordTTL: 3600},
		},
	}

	err := client.ApplyChanges(changes)
	if err != nil {
		t.Fatalf("ApplyChanges(update+create) returned error: %v", err)
	}

	m.mu.Lock()
	count := m.requestCount
	aRecs := m.zone[zoneKey("a", "A")]
	bRecs := m.zone[zoneKey("b", "A")]
	m.mu.Unlock()

	if count != 1 {
		t.Errorf("expected exactly 1 bulk request to the domain, got %d", count)
	}
	if len(aRecs) != 1 || aRecs[0] != "2.2.2.2" {
		t.Errorf("a.example.com A must be updated to 2.2.2.2, got %v", aRecs)
	}
	if len(bRecs) != 1 || bRecs[0] != "3.3.3.3" {
		t.Errorf("b.example.com A must be created as 3.3.3.3, got %v", bRecs)
	}
}

// Test 4 (dry-run safety): dry-run must not touch the API at all.
func TestApplyChanges_DryRunMakesNoRequests(t *testing.T) {
	m := newDesecMock()
	srv := m.server(t)
	client := newTestClient(t, srv)
	client.dryRun = true

	changes := plan.Changes{
		Create: []*endpoint.Endpoint{
			{DNSName: "x.example.com", RecordType: "A", Targets: endpoint.Targets{"9.9.9.9"}, RecordTTL: 3600},
		},
		UpdateNew: []*endpoint.Endpoint{
			{DNSName: "y.example.com", RecordType: "A", Targets: endpoint.Targets{"8.8.8.8"}, RecordTTL: 3600},
		},
		Delete: []*endpoint.Endpoint{
			{DNSName: "z.example.com", RecordType: "A", Targets: endpoint.Targets{"7.7.7.7"}, RecordTTL: 3600},
		},
	}

	if err := client.ApplyChanges(changes); err != nil {
		t.Fatalf("dry-run ApplyChanges returned error: %v", err)
	}

	m.mu.Lock()
	count := m.requestCount
	m.mu.Unlock()
	if count != 0 {
		t.Errorf("dry-run must make no API requests, got %d", count)
	}
}
