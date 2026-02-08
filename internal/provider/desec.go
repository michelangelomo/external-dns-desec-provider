package provider

import (
	"context"
	"strings"

	"github.com/michelangelomo/external-dns-desec-provider/internal/config"
	"github.com/nrdcg/desec"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/publicsuffix"
	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/plan"
)

type DesecClient struct {
	client        *desec.Client
	ctx           context.Context
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

	ctx := context.Background()
	client := &DesecClient{
		client:        desec.New(config.APIToken, desec.ClientOptions{RetryMax: 2}),
		ctx:           ctx,
		dryRun:        config.DryRun,
		defaultTTL:    config.DefaultTTL,
		domainFilters: config.DomainFilters,
	}
	return client, nil
}

func (d *DesecClient) GetDomains() ([]desec.Domain, error) {
	return d.client.Domains.GetAll(d.ctx)
}

func (d *DesecClient) GetRecords(domain string) ([]desec.RRSet, error) {
	return d.client.Records.GetAll(d.ctx, domain, nil)
}

func (d *DesecClient) ApplyChanges(changes plan.Changes) error {
	// Create new records
	for domain, endpoints := range d.mapEndpointsByHostname(changes.Create) {
		var toCreate []desec.RRSet
		// Convert endpoint from external-dns to desec.RRSet
		for _, endpoint := range endpoints {
			toCreate = append(toCreate, *convertEndpointToRRSet(endpoint, domain, d.defaultTTL))
		}

		if d.dryRun {
			log.Infof("dryrun: at this point, the following records would be created: %v", toCreate)
		} else {
			// Create the records in desec
			_, err := d.client.Records.BulkCreate(d.ctx, domain, toCreate)
			if err != nil {
				log.Errorf("failed to create records for domain %s: %v, payload: %v", domain, err, toCreate)
				return err
			}
		}
	}

	// Update existing records
	for domain, endpoints := range d.mapEndpointsByHostname(changes.UpdateNew) {
		var toUpdate []desec.RRSet
		// Convert endpoint from external-dns to desec.RRSet
		for _, endpoint := range endpoints {
			toUpdate = append(toUpdate, *convertEndpointToRRSet(endpoint, domain, d.defaultTTL))
		}

		if d.dryRun {
			log.Infof("dryrun: at this point, the following records would be updated: %v", toUpdate)
		} else {
			// Update records in desec with bulk ops
			_, err := d.client.Records.BulkUpdate(d.ctx, desec.FullResource, domain, toUpdate)
			if err != nil {
				log.Errorf("failed to update records for domain %s: %v, payload: %v", domain, err, toUpdate)
				return err
			}
		}
	}

	// Delete records
	for domain, endpoints := range d.mapEndpointsByHostname(changes.Delete) {
		var toDelete []desec.RRSet
		// Convert endpoint from external-dns to desec.RRSet
		for _, endpoint := range endpoints {
			toDelete = append(toDelete, *convertEndpointToRRSet(endpoint, domain, d.defaultTTL))
		}

		if d.dryRun {
			log.Infof("dryrun: at this point, the following records would be deleted: %v", toDelete)
		} else {
			// Delete records in desec with bulk ops
			err := d.client.Records.BulkDelete(d.ctx, domain, toDelete)
			if err != nil {
				log.Errorf("failed to delete records for domain %s: %v, payload: %v", domain, err, toDelete)
				return err
			}
		}
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
			adjusted.RecordTTL = endpoint.TTL(d.defaultTTL)
		}

		// Copy and adjust targets
		adjusted.Targets = make(endpoint.Targets, len(ep.Targets))
		for i, target := range ep.Targets {
			rec := target
			// Ensure CNAME records end with a dot
			if ep.RecordType == "CNAME" && !strings.HasSuffix(rec, ".") {
				rec = rec + "."
			}
			adjusted.Targets[i] = rec
		}

		adjustedEndpoints = append(adjustedEndpoints, adjusted)
	}

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
		log.Debugf("mapEndpointsByHostname(%s)", ep.DNSName)
		// Trim any trailing dot before parsing
		dnsName := strings.TrimSuffix(ep.DNSName, ".")

		// Find the longest matching domain from the filters
		matchedDomain := findMatchingDomain(dnsName, d.domainFilters)
		if matchedDomain == "" {
			log.Warnf("no matching domain filter found for %s", ep.DNSName)
			continue
		}

		result[matchedDomain] = append(result[matchedDomain], ep)
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

	// Set RecordTTL to default if is empty or less than minimum TTL
	if ep.RecordTTL == 0 || ep.RecordTTL < minimumTTL {
		ep.RecordTTL = endpoint.TTL(defaultTTL)
	}

	return &desec.RRSet{
		SubName: subname,
		Type:    ep.RecordType,
		Records: records,
		TTL:     int(ep.RecordTTL),
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
