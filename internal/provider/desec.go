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
	client     *desec.Client
	ctx        context.Context
	dryRun     bool
	defaultTTL int
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
		client:     desec.New(config.APIToken, desec.ClientOptions{}),
		ctx:        ctx,
		dryRun:     config.DryRun,
		defaultTTL: config.DefaultTTL,
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
	for domain, endpoints := range mapEndpointsByHostname(changes.Create) {
		var toCreate []desec.RRSet
		// Convert endpoint from external-dns to desec.RRSet
		for _, endpoint := range endpoints {
			toCreate = append(toCreate, *convertEndpointToRRSet(endpoint, d.defaultTTL))
		}

		if d.dryRun {
			log.Infof("dryrun: at this point, the following records would be created: %v", toCreate)
		} else {
			// Create the records in desec
			_, err := d.client.Records.BulkCreate(d.ctx, domain, toCreate)
			if err != nil {
				log.Error("failed to create records", err)
			}
		}
	}

	// Update existing records
	for domain, endpoints := range mapEndpointsByHostname(changes.UpdateNew) {
		var toUpdate []desec.RRSet
		// Convert endpoint from external-dns to desec.RRSet
		for _, endpoint := range endpoints {
			toUpdate = append(toUpdate, *convertEndpointToRRSet(endpoint, d.defaultTTL))
		}

		if d.dryRun {
			log.Infof("dryrun: at this point, the following records would be updated: %v", toUpdate)
		} else {
			// Update records in desec with bulk ops
			_, err := d.client.Records.BulkUpdate(d.ctx, desec.FullResource, domain, toUpdate)
			if err != nil {
				log.Error("failed to update records", err)
			}
		}
	}

	// Delete records
	for domain, endpoints := range mapEndpointsByHostname(changes.Delete) {
		var toDelete []desec.RRSet
		// Convert endpoint from external-dns to desec.RRSet
		for _, endpoint := range endpoints {
			toDelete = append(toDelete, *convertEndpointToRRSet(endpoint, d.defaultTTL))
		}

		if d.dryRun {
			log.Infof("dryrun: at this point, the following records would be deleted: %v", toDelete)
		} else {
			// Delete records in desec with bulk ops
			err := d.client.Records.BulkDelete(d.ctx, domain, toDelete)
			if err != nil {
				log.Error("failed to delete records", err)
				return err
			}
		}
	}

	return nil
}

func (d *DesecClient) AdjustEndpoints(endpoints []*endpoint.Endpoint) ([]*endpoint.Endpoint, error) {
	var updatedEndpoint []*endpoint.Endpoint
	// Reconcile existing records
	for domain, endpoints := range mapEndpointsByHostname(endpoints) {
		var toReconcile []desec.RRSet
		// Convert endpoint from external-dns to desec.RRSet
		for _, endpoint := range endpoints {
			toReconcile = append(toReconcile, *convertEndpointToRRSet(endpoint, d.defaultTTL))
		}

		if d.dryRun {
			log.Infof("dryrun: at this point, the following records would be reconciled: %v", toReconcile)
			// In dry run mode, we don't actually reconcile, just return the endpoints
			updatedEndpoint = append(updatedEndpoint, endpoints...)
		} else {
			// Update records in desec with bulk ops
			updated, err := d.client.Records.BulkUpdate(d.ctx, desec.FullResource, domain, toReconcile)
			if err != nil {
				log.Error("failed to update records", err)
				return []*endpoint.Endpoint{}, err
			}
			for _, u := range updated {
				updatedEndpoint = append(updatedEndpoint, convertRRSetToEndpoint(&u, domain))
			}
		}
	}
	return updatedEndpoint, nil
}

// mapEndpointsByHostname extracts hostnames from DNSName and maps them to a slice of corresponding Endpoints
func mapEndpointsByHostname(endpoints []*endpoint.Endpoint) map[string][]*endpoint.Endpoint {
	result := make(map[string][]*endpoint.Endpoint)

	for _, ep := range endpoints {
		if ep == nil || ep.DNSName == "" {
			continue
		}

		// Trim any trailing dot before parsing
		dnsName := strings.TrimSuffix(ep.DNSName, ".")

		parsed, err := publicsuffix.EffectiveTLDPlusOne(dnsName)
		if err != nil {
			log.Warnf("failed to parse URL %s: %v", ep.DNSName, err)
			continue
		}

		result[parsed] = append(result[parsed], ep)
	}

	return result
}

// convertEndpointToRRSet converts an Endpoint to an RRSet
func convertEndpointToRRSet(ep *endpoint.Endpoint, defaultTTL int) *desec.RRSet {
	if ep == nil {
		return nil
	}

	_, subname := extractDomainAndSubname(ep.DNSName)

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

// extractDomainAndSubname splits a DNS name into domain and subname.
// Example: "www.example.com" -> domain: "example.com", subname: "www"
func extractDomainAndSubname(fqdn string) (domain string, subname string) {
	parts := strings.Split(fqdn, ".")
	if len(parts) < 2 {
		// fallback for invalid names
		return fqdn, ""
	}
	domain = strings.Join(parts[len(parts)-2:], ".")
	if len(parts) > 2 {
		subname = strings.Join(parts[:len(parts)-2], ".")
	}
	return
}
