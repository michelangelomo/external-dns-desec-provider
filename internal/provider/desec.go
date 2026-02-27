package provider

import (
	"context"
	"errors"
	"strings"

	"github.com/michelangelomo/external-dns-desec-provider/internal/config"
	"github.com/michelangelomo/external-dns-desec-provider/internal/desec"
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
}

const (
	minimumTTL = 3600 // Minimum TTL for desec is 3600 seconds
)

func CreateDesecClient(config config.Config) (*DesecClient, error) {
	if config.DefaultTTL < minimumTTL {
		log.Warnf("default TTL %d is less than the minimum required TTL %d, setting to %d", config.DefaultTTL, minimumTTL, minimumTTL)
		config.DefaultTTL = minimumTTL
	}

	client := &DesecClient{
		client:        desec.NewClient(config.APIToken),
		dryRun:        config.DryRun,
		defaultTTL:    config.DefaultTTL,
		domainFilters: config.DomainFilters,
	}
	return client, nil
}

// GetEndpoints fetches all RRSets for a domain and converts them to external-dns Endpoints.
func (d *DesecClient) GetEndpoints(domain string) ([]*endpoint.Endpoint, error) {
	log.Debugf("fetching records for domain %s", domain)
	rrsets, err := d.client.GetRecords(context.Background(), domain)
	if err != nil {
		return nil, err
	}
	log.Debugf("fetched %d rrsets for domain %s", len(rrsets), domain)

	endpoints := make([]*endpoint.Endpoint, 0, len(rrsets))
	for _, rrset := range rrsets {
		ep := convertRRSetToEndpoint(&rrset, domain)
		log.Debugf("converted rrset %s/%s -> endpoint %s/%s (targets: %v, ttl: %d)",
			rrset.SubName, rrset.Type, ep.DNSName, ep.RecordType, ep.Targets, ep.RecordTTL)
		endpoints = append(endpoints, ep)
	}
	return endpoints, nil
}

func (d *DesecClient) ApplyChanges(changes plan.Changes) error {
	log.Debugf("applying changes: %d creates, %d updates, %d deletes",
		len(changes.Create), len(changes.UpdateNew), len(changes.Delete))

	var errs []error

	// Create new records
	for domain, endpoints := range d.mapEndpointsByHostname(changes.Create) {
		var toCreate []desec.RRSet
		for _, endpoint := range endpoints {
			toCreate = append(toCreate, *convertEndpointToRRSet(endpoint, domain, d.defaultTTL))
		}

		if d.dryRun {
			log.Infof("dryrun: would create %d records for domain %s: %v", len(toCreate), domain, toCreate)
		} else {
			log.Debugf("creating %d records for domain %s: %v", len(toCreate), domain, toCreate)
			_, err := d.client.BulkCreateRecords(context.Background(), domain, toCreate)
			if err != nil {
				logDomainError(domain, "create", err)
				errs = append(errs, err)
				continue
			}
			log.Debugf("successfully created %d records for domain %s", len(toCreate), domain)
		}
	}

	// Update existing records
	for domain, endpoints := range d.mapEndpointsByHostname(changes.UpdateNew) {
		var toUpdate []desec.RRSet
		for _, endpoint := range endpoints {
			toUpdate = append(toUpdate, *convertEndpointToRRSet(endpoint, domain, d.defaultTTL))
		}

		if d.dryRun {
			log.Infof("dryrun: would update %d records for domain %s: %v", len(toUpdate), domain, toUpdate)
		} else {
			log.Debugf("updating %d records for domain %s: %v", len(toUpdate), domain, toUpdate)
			_, err := d.client.BulkUpdateRecords(context.Background(), domain, toUpdate)
			if err != nil {
				logDomainError(domain, "update", err)
				errs = append(errs, err)
				continue
			}
			log.Debugf("successfully updated %d records for domain %s", len(toUpdate), domain)
		}
	}

	// Delete records
	for domain, endpoints := range d.mapEndpointsByHostname(changes.Delete) {
		var toDelete []desec.RRSet
		for _, endpoint := range endpoints {
			toDelete = append(toDelete, *convertEndpointToRRSet(endpoint, domain, d.defaultTTL))
		}

		if d.dryRun {
			log.Infof("dryrun: would delete %d records for domain %s: %v", len(toDelete), domain, toDelete)
		} else {
			log.Debugf("deleting %d records for domain %s: %v", len(toDelete), domain, toDelete)
			err := d.client.BulkDeleteRecords(context.Background(), domain, toDelete)
			if err != nil {
				logDomainError(domain, "delete", err)
				errs = append(errs, err)
				continue
			}
			log.Debugf("successfully deleted %d records for domain %s", len(toDelete), domain)
		}
	}

	return errors.Join(errs...)
}

// logDomainError logs an error for a domain operation, using Warn for rate limits and Error for other errors.
func logDomainError(domain, operation string, err error) {
	var rle *desec.RateLimitError
	if errors.As(err, &rle) {
		log.Warnf("rate limited while %s records for domain %s: retry after %d seconds", operation, domain, rle.RetryAfter)
	} else {
		log.Errorf("failed to %s records for domain %s: %v", operation, domain, err)
	}
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

	// Compose DNSName from subname and domain
	var dnsName string
	if rrset.SubName == "" {
		dnsName = domain
	} else {
		dnsName = rrset.SubName + "." + domain
	}
	dnsName = strings.TrimSuffix(dnsName, ".") + "."

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
