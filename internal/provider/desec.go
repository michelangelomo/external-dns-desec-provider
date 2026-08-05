package provider

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/michelangelomo/external-dns-desec-provider/internal/config"
	"github.com/nrdcg/desec"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/publicsuffix"
	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/plan"
)

type DesecClient struct {
	client        *desec.Client
	dryRun        bool
	defaultTTL    int
	domainFilters []string
	rateLimit     *rateLimitTracker

	cacheMu sync.Mutex
	cache   map[string]cachedEndpoints
}

type cachedEndpoints struct {
	endpoints []*endpoint.Endpoint
	fetchedAt time.Time
}

const (
	minimumTTL = 3600 // Minimum TTL for desec is 3600 seconds

	// maxCacheStaleness caps how old a last-known-good record set may be before
	// it is no longer served during a throttle window. Past it we prefer a 500
	// (retried next interval) over feeding external-dns a stale zone under
	// --policy=sync, which could delete records that in fact still exist.
	maxCacheStaleness = 24 * time.Hour
)

// retryableLogger adapts logrus to retryablehttp.LeveledLogger so the retry
// client's status codes and wait durations surface in the app's log stream.
type retryableLogger struct{}

func (retryableLogger) Error(msg string, kv ...any) { log.WithFields(kvFields(kv)).Error(msg) }
func (retryableLogger) Warn(msg string, kv ...any)  { log.WithFields(kvFields(kv)).Warn(msg) }
func (retryableLogger) Info(msg string, kv ...any)  { log.WithFields(kvFields(kv)).Info(msg) }
func (retryableLogger) Debug(msg string, kv ...any) { log.WithFields(kvFields(kv)).Debug(msg) }

func kvFields(kv []any) log.Fields {
	fields := log.Fields{}
	for i := 0; i+1 < len(kv); i += 2 {
		key, ok := kv[i].(string)
		if !ok {
			key = fmt.Sprintf("%v", kv[i])
		}
		fields[key] = kv[i+1]
	}
	return fields
}

func CreateDesecClient(config config.Config) (*DesecClient, error) {
	if config.DefaultTTL < minimumTTL {
		log.Warnf("default TTL %d is less than the minimum required TTL %d, setting to %d", config.DefaultTTL, minimumTTL, minimumTTL)
		config.DefaultTTL = minimumTTL
	}

	tracker := newRateLimitTracker()
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &rateLimitTransport{
			inner:     http.DefaultTransport,
			tracker:   tracker,
			proactive: newProactiveLimiter(tracker.now),
		},
	}

	client := &DesecClient{
		client: desec.New(config.APIToken, desec.ClientOptions{
			RetryMax:   2,
			HTTPClient: httpClient,
			// Without a logger retryablehttp swallows the 429 and its retry
			// wait, which is how the ~12.5h sleep was invisible in the logs.
			Logger: retryableLogger{},
		}),
		dryRun:        config.DryRun,
		defaultTTL:    config.DefaultTTL,
		domainFilters: config.DomainFilters,
		rateLimit:     tracker,
		cache:         make(map[string]cachedEndpoints),
	}
	return client, nil
}

func (d *DesecClient) GetDomains(ctx context.Context) ([]desec.Domain, error) {
	return d.client.Domains.GetAll(ctx)
}

// checkThrottle returns a *RateLimitError while a throttle window observed from
// a prior 429 is still open, so a call can skip the API entirely: hitting deSEC
// again would only burn more of the daily quota and return another long
// Retry-After. op names the skipped operation for the log line.
func (d *DesecClient) checkThrottle(op string) *RateLimitError {
	remaining := d.rateLimit.wait()
	if remaining <= 0 {
		return nil
	}
	log.Warnf("deSEC rate limit active; skipping %s (retry after %s)", op, remaining)
	return &RateLimitError{RetryAfter: remaining}
}

// GetEndpoints fetches all RRSets for a domain and converts them to external-dns Endpoints.
// The caller's context is threaded through to the deSEC call so external-dns's
// webhook read timeout can interrupt a request stuck retrying a 429 -- the
// deSEC library sleeps the raw Retry-After (up to ~12.5h) between retries and
// only wakes on ctx cancellation or the timer.
func (d *DesecClient) GetEndpoints(ctx context.Context, domain string) ([]*endpoint.Endpoint, error) {
	if rle := d.checkThrottle("/records fetch for " + domain); rle != nil {
		return nil, rle
	}

	log.Infof("fetching records for domain %s", domain)
	rrsets, err := d.client.Records.GetAll(ctx, domain, nil)
	if err != nil {
		return nil, err
	}
	log.Infof("fetched %d rrsets for domain %s", len(rrsets), domain)

	endpoints := make([]*endpoint.Endpoint, 0, len(rrsets))
	for _, rrset := range rrsets {
		ep := convertRRSetToEndpoint(&rrset, domain)
		log.Debugf("converted rrset %s/%s -> endpoint %s/%s (targets: %v, ttl: %d)",
			rrset.SubName, rrset.Type, ep.DNSName, ep.RecordType, ep.Targets, ep.RecordTTL)
		endpoints = append(endpoints, ep)
	}

	// Remember this successful fetch as last-known-good so a later throttle
	// window can be answered from cache instead of a 500.
	d.cacheMu.Lock()
	d.cache[domain] = cachedEndpoints{endpoints: endpoints, fetchedAt: d.rateLimit.now()}
	d.cacheMu.Unlock()

	return endpoints, nil
}

// Throttled reports whether a deSEC throttle window observed from a prior 429 is
// still open. Handlers consult it to decide whether serving stale cached records
// is warranted.
func (d *DesecClient) Throttled() bool {
	return d.rateLimit.wait() > 0
}

// CachedEndpoints returns last-known-good endpoints for every requested domain,
// but only all-or-nothing: if any domain has never been fetched successfully or
// its cache is older than maxCacheStaleness, it returns ok=false. Serving a
// partial set under --policy=sync would make external-dns recreate the missing
// domain's records, so a gap must fall through to a 500 instead.
func (d *DesecClient) CachedEndpoints(domains []string) ([]*endpoint.Endpoint, bool) {
	d.cacheMu.Lock()
	defer d.cacheMu.Unlock()

	now := d.rateLimit.now()
	endpoints := []*endpoint.Endpoint{}
	for _, domain := range domains {
		entry, ok := d.cache[domain]
		if !ok {
			return nil, false
		}
		if now.Sub(entry.fetchedAt) > maxCacheStaleness {
			log.Warnf("cached records for %s are older than %s; not serving stale zone", domain, maxCacheStaleness)
			return nil, false
		}
		endpoints = append(endpoints, entry.endpoints...)
	}
	return endpoints, true
}

func (d *DesecClient) ApplyChanges(ctx context.Context, changes plan.Changes) error {
	if rle := d.checkThrottle("ApplyChanges"); rle != nil {
		return rle
	}

	log.Debugf("applying changes: %d creates, %d updates, %d deletes",
		len(changes.Create), len(changes.UpdateNew), len(changes.Delete))

	// deSEC bulk operations are atomic and validate the *resulting* zone
	// state, so we merge creates, updates, and deletes for each domain into a
	// single PUT (desec.FullResource). This avoids the non-atomic Create-then-
	// Delete ordering that breaks record-type changes: a retype reaches us as
	// Delete(old A) + Create(new CNAME) at the same subname, and posting the
	// CNAME while the A still exists is rejected by deSEC (CNAME may not
	// coexist with other types). Encoding the deletion as records:[] in the
	// same request lets deSEC validate the final state (A gone, CNAME present)
	// and accept it. BulkUpdate(FullResource, ...) only touches the rrsets in
	// the request, so unrelated records are untouched.
	type bulkChanges struct {
		create    []desec.RRSet
		updateNew []desec.RRSet
		delete    []desec.RRSet
	}
	merged := make(map[string]*bulkChanges)

	get := func(domain string) *bulkChanges {
		bc := merged[domain]
		if bc == nil {
			bc = &bulkChanges{}
			merged[domain] = bc
		}
		return bc
	}

	for domain, endpoints := range d.mapEndpointsByHostname(changes.Create) {
		bc := get(domain)
		for _, ep := range endpoints {
			bc.create = append(bc.create, *convertEndpointToRRSet(ep, domain, d.defaultTTL))
		}
	}
	for domain, endpoints := range d.mapEndpointsByHostname(changes.UpdateNew) {
		bc := get(domain)
		for _, ep := range endpoints {
			bc.updateNew = append(bc.updateNew, *convertEndpointToRRSet(ep, domain, d.defaultTTL))
		}
	}
	for domain, endpoints := range d.mapEndpointsByHostname(changes.Delete) {
		bc := get(domain)
		for _, ep := range endpoints {
			rrset := *convertEndpointToRRSet(ep, domain, d.defaultTTL)
			// Encode deletion as an empty record set so the bulk PUT removes
			// it while validating the final zone state.
			rrset.Records = []string{}
			bc.delete = append(bc.delete, rrset)
		}
	}

	for domain, bc := range merged {
		toApply := make([]desec.RRSet, 0, len(bc.create)+len(bc.updateNew)+len(bc.delete))
		toApply = append(toApply, bc.create...)
		toApply = append(toApply, bc.updateNew...)
		toApply = append(toApply, bc.delete...)

		if d.dryRun {
			log.Infof("dryrun: would apply %d changes for domain %s (%d create, %d update, %d delete): %v",
				len(toApply), domain, len(bc.create), len(bc.updateNew), len(bc.delete), toApply)
			continue
		}

		log.Debugf("applying %d changes for domain %s (%d create, %d update, %d delete): %v",
			len(toApply), domain, len(bc.create), len(bc.updateNew), len(bc.delete), toApply)
		_, err := d.client.Records.BulkUpdate(ctx, desec.FullResource, domain, toApply)
		if err != nil {
			log.Errorf("failed to apply changes for domain %s: %v, payload: %v", domain, err, toApply)
			return err
		}
		log.Debugf("successfully applied %d changes for domain %s", len(toApply), domain)
	}

	return nil
}

// AdjustEndpoints adjusts endpoints to be compatible with deSEC requirements.
// This method is called by external-dns on every reconciliation loop BEFORE
// change detection.
// - Ensures TTL meets the minimum requirement (3600 seconds)
// - Adds trailing dots to CNAME targets
// - Filters out endpoints that don't match the domain filters
func (d *DesecClient) AdjustEndpoints(endpoints []*endpoint.Endpoint) ([]*endpoint.Endpoint, error) {
	if endpoints == nil {
		return []*endpoint.Endpoint{}, nil
	}

	log.Debugf("adjusting %d endpoints", len(endpoints))
	adjustedEndpoints := make([]*endpoint.Endpoint, 0, len(endpoints))

	for _, ep := range endpoints {
		if ep == nil {
			continue
		}

		// Check if this endpoint matches our domain filters
		matchedDomain := findMatchingDomain(ep.DNSName, d.domainFilters)
		if matchedDomain == "" {
			log.Warnf("no matching domain filter found for %s", ep.DNSName)
			continue
		}

		// Create a copy of the endpoint to avoid modifying the original
		adjusted := &endpoint.Endpoint{
			DNSName:          ep.DNSName,
			RecordType:       ep.RecordType,
			SetIdentifier:    ep.SetIdentifier,
			RecordTTL:        ep.RecordTTL,
			Labels:           ep.Labels,
			ProviderSpecific: ep.ProviderSpecific,
		}

		// Adjust TTL to meet minimum requirement
		if adjusted.RecordTTL == 0 || int(adjusted.RecordTTL) < minimumTTL {
			log.Debugf("adjusting TTL for %s/%s: %d -> %d", ep.DNSName, ep.RecordType, ep.RecordTTL, d.defaultTTL)
			adjusted.RecordTTL = endpoint.TTL(d.defaultTTL)
		}

		// Copy and adjust targets
		adjusted.Targets = make(endpoint.Targets, len(ep.Targets))
		for i, target := range ep.Targets {
			rec := target
			// Ensure CNAME records end with a dot
			if ep.RecordType == "CNAME" && !strings.HasSuffix(rec, ".") {
				log.Debugf("appending trailing dot to CNAME target for %s: %s -> %s.", ep.DNSName, rec, rec)
				rec = rec + "."
			}
			adjusted.Targets[i] = rec
		}

		adjustedEndpoints = append(adjustedEndpoints, adjusted)
	}

	log.Debugf("adjusted %d endpoints (filtered from %d)", len(adjustedEndpoints), len(endpoints))
	return adjustedEndpoints, nil
}

// findMatchingDomain finds the longest matching domain from the domain filters
// Ex with filters ["sub.example.com", "example.com"]:
// - "foo.sub.example.com" matches "sub.example.com"
// - "bar.example.com" matches "example.com"
// - "baz.test.example.com" matches "example.com" (test.example.com is not in filters)
func findMatchingDomain(dnsName string, domainFilters []string) string {
	dnsName = strings.TrimSuffix(dnsName, ".")

	var longestMatch string
	for _, filter := range domainFilters {
		filter = strings.TrimSuffix(filter, ".")
		// Check if dnsName ends with the filter (exact match or subdomain)
		if dnsName == filter || strings.HasSuffix(dnsName, "."+filter) {
			// Keep the longest match
			if len(filter) > len(longestMatch) {
				longestMatch = filter
			}
		}
	}

	return longestMatch
}

// mapEndpointsByHostname extracts hostnames from DNSName and maps them to a slice of corresponding Endpoints
func (d *DesecClient) mapEndpointsByHostname(endpoints []*endpoint.Endpoint) map[string][]*endpoint.Endpoint {
	result := make(map[string][]*endpoint.Endpoint)

	for _, ep := range endpoints {
		if ep == nil || ep.DNSName == "" {
			continue
		}
		// Trim any trailing dot before parsing
		dnsName := strings.TrimSuffix(ep.DNSName, ".")

		// Find the longest matching domain from the filters
		matchedDomain := findMatchingDomain(dnsName, d.domainFilters)
		if matchedDomain == "" {
			log.Warnf("no matching domain filter found for %s", ep.DNSName)
			continue
		}

		log.Debugf("mapped endpoint %s/%s -> domain %s", ep.DNSName, ep.RecordType, matchedDomain)
		result[matchedDomain] = append(result[matchedDomain], ep)
	}

	for domain, eps := range result {
		log.Debugf("domain %s: %d endpoints", domain, len(eps))
	}

	return result
}

// convertEndpointToRRSet converts an Endpoint to an RRSet
// domain should be the matched domain filter for this endpoint
func convertEndpointToRRSet(ep *endpoint.Endpoint, domain string, defaultTTL int) *desec.RRSet {
	if ep == nil {
		return nil
	}

	subname := extractSubname(ep.DNSName, domain)

	records := make([]string, len(ep.Targets))
	for i, target := range ep.Targets {
		rec := target
		// Ensure CNAME records end with a dot
		if ep.RecordType == "CNAME" && !strings.HasSuffix(rec, ".") {
			rec = rec + "."
		}
		records[i] = rec
	}

	// Use default TTL if the endpoint's TTL is empty or less than minimum TTL
	ttl := int(ep.RecordTTL)
	if ep.RecordTTL == 0 || ep.RecordTTL < minimumTTL {
		ttl = defaultTTL
	}

	return &desec.RRSet{
		SubName: subname,
		Type:    ep.RecordType,
		Records: records,
		TTL:     ttl,
	}
}

// convertRRSetToEndpoint converts an RRSet to an Endpoint
func convertRRSetToEndpoint(rrset *desec.RRSet, domain string) *endpoint.Endpoint {
	if rrset == nil {
		return nil
	}

	// Compose DNSName from subname and domain. external-dns sources emit
	// DNSName without a trailing dot, and external-dns's TXT registry
	// matches companion records by exact-string DNSName -- if /records
	// returns a dotted form, the registry sets providerSpecific
	// txt/force-update=true on every reconcile and the plan calculator
	// emits a no-op Update for every record.
	var dnsName string
	if rrset.SubName == "" {
		dnsName = domain
	} else {
		dnsName = rrset.SubName + "." + domain
	}
	dnsName = strings.TrimSuffix(dnsName, ".")

	targets := make(endpoint.Targets, len(rrset.Records))
	copy(targets, rrset.Records)

	return &endpoint.Endpoint{
		DNSName:    dnsName,
		RecordType: rrset.Type,
		Targets:    targets,
		RecordTTL:  endpoint.TTL(rrset.TTL),
	}
}

// extractSubname extracts the subdomain part from a DNS name and domain
// extractSubname("foo.sub.example.com", "sub.example.com") -> "foo"
// extractSubname("sub.example.com", "sub.example.com") -> ""
func extractSubname(dnsName, domain string) string {
	dnsName = strings.TrimSuffix(dnsName, ".")
	domain = strings.TrimSuffix(domain, ".")

	if dnsName == domain {
		return "" // No subdomain, this is the apex
	}

	subname := strings.TrimSuffix(dnsName, "."+domain)
	return subname
}

func extractDomainAndSubname(fqdn string) (domain, subname string, err error) {
	// Get the eTLD+1
	domain, err = publicsuffix.EffectiveTLDPlusOne(fqdn)
	if err != nil {
		return domain, "", err
	}
	if fqdn == domain {
		return domain, "", nil // No subdomain
	}
	subname = strings.TrimSuffix(fqdn, "."+domain)
	return domain, subname, nil
}

// extractDomainAndSubname splits a DNS name into domain and subname.
// Example: "www.example.com" -> domain: "example.com", subname: "www"
// func extractDomainAndSubname2(fqdn string) (domain string, subname string) {
//	parts := strings.Split(fqdn, ".")
//	if len(parts) < 2 {
//		// fallback for invalid names
//		return fqdn, ""
//	}
//	domain = strings.Join(parts[len(parts)-2:], ".")
//	if len(parts) > 2 {
//		subname = strings.Join(parts[:len(parts)-2], ".")
//	}
//	return
//}
