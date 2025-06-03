package provider

import (
	"reflect"
	"testing"

	"github.com/michelangelomo/external-dns-desec-provider/internal/config"
	"github.com/nrdcg/desec"
	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/plan"
)

func TestCreateDesecClient(t *testing.T) {
	tests := []struct {
		name   string
		config config.Config
	}{
		{
			name: "Valid configuration",
			config: config.Config{
				APIToken:      "test-token",
				DomainFilters: []string{"example.com"},
				DryRun:        false,
			},
		},
		{
			name: "Dry run configuration",
			config: config.Config{
				APIToken:      "test-token",
				DomainFilters: []string{"example.com"},
				DryRun:        true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := CreateDesecClient(tt.config)
			if err != nil {
				t.Errorf("CreateDesecClient() error = %v", err)
			}
			//nolint:staticcheck
			if client == nil {
				t.Error("CreateDesecClient() returned nil client")
			}
			//nolint:staticcheck
			if client.dryRun != tt.config.DryRun {
				t.Errorf("CreateDesecClient() dryRun = %v, want %v", client.dryRun, tt.config.DryRun)
			}
		})
	}
}

func TestMapEndpointsByHostname(t *testing.T) {
	tests := []struct {
		name      string
		endpoints []*endpoint.Endpoint
		expected  map[string][]*endpoint.Endpoint
	}{
		{
			name: "Single domain",
			endpoints: []*endpoint.Endpoint{
				{
					DNSName:    "www.example.com",
					RecordType: "A",
					Targets:    endpoint.Targets{"192.0.2.1"},
				},
				{
					DNSName:    "api.example.com",
					RecordType: "A",
					Targets:    endpoint.Targets{"192.0.2.2"},
				},
			},
			expected: map[string][]*endpoint.Endpoint{
				"example.com": {
					{
						DNSName:    "www.example.com",
						RecordType: "A",
						Targets:    endpoint.Targets{"192.0.2.1"},
					},
					{
						DNSName:    "api.example.com",
						RecordType: "A",
						Targets:    endpoint.Targets{"192.0.2.2"},
					},
				},
			},
		},
		{
			name: "Multiple domains",
			endpoints: []*endpoint.Endpoint{
				{
					DNSName:    "www.example.com",
					RecordType: "A",
					Targets:    endpoint.Targets{"192.0.2.1"},
				},
				{
					DNSName:    "www.test.org",
					RecordType: "A",
					Targets:    endpoint.Targets{"192.0.2.2"},
				},
			},
			expected: map[string][]*endpoint.Endpoint{
				"example.com": {
					{
						DNSName:    "www.example.com",
						RecordType: "A",
						Targets:    endpoint.Targets{"192.0.2.1"},
					},
				},
				"test.org": {
					{
						DNSName:    "www.test.org",
						RecordType: "A",
						Targets:    endpoint.Targets{"192.0.2.2"},
					},
				},
			},
		},
		{
			name: "With trailing dot",
			endpoints: []*endpoint.Endpoint{
				{
					DNSName:    "www.example.com.",
					RecordType: "A",
					Targets:    endpoint.Targets{"192.0.2.1"},
				},
			},
			expected: map[string][]*endpoint.Endpoint{
				"example.com": {
					{
						DNSName:    "www.example.com.",
						RecordType: "A",
						Targets:    endpoint.Targets{"192.0.2.1"},
					},
				},
			},
		},
		{
			name:      "Empty endpoints",
			endpoints: []*endpoint.Endpoint{},
			expected:  map[string][]*endpoint.Endpoint{},
		},
		{
			name: "Nil endpoint",
			endpoints: []*endpoint.Endpoint{
				nil,
				{
					DNSName:    "www.example.com",
					RecordType: "A",
					Targets:    endpoint.Targets{"192.0.2.1"},
				},
			},
			expected: map[string][]*endpoint.Endpoint{
				"example.com": {
					{
						DNSName:    "www.example.com",
						RecordType: "A",
						Targets:    endpoint.Targets{"192.0.2.1"},
					},
				},
			},
		},
		{
			name: "Empty DNS name",
			endpoints: []*endpoint.Endpoint{
				{
					DNSName:    "",
					RecordType: "A",
					Targets:    endpoint.Targets{"192.0.2.1"},
				},
				{
					DNSName:    "www.example.com",
					RecordType: "A",
					Targets:    endpoint.Targets{"192.0.2.2"},
				},
			},
			expected: map[string][]*endpoint.Endpoint{
				"example.com": {
					{
						DNSName:    "www.example.com",
						RecordType: "A",
						Targets:    endpoint.Targets{"192.0.2.2"},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapEndpointsByHostname(tt.endpoints)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("mapEndpointsByHostname() = %+v, want %+v", result, tt.expected)
			}
		})
	}
}

func TestExtractDomainAndSubname(t *testing.T) {
	tests := []struct {
		name           string
		fqdn           string
		expectedDomain string
		expectedSub    string
	}{
		{
			name:           "Standard subdomain",
			fqdn:           "www.example.com",
			expectedDomain: "example.com",
			expectedSub:    "www",
		},
		{
			name:           "Deep subdomain",
			fqdn:           "api.v1.example.com",
			expectedDomain: "example.com",
			expectedSub:    "api.v1",
		},
		{
			name:           "Root domain",
			fqdn:           "example.com",
			expectedDomain: "example.com",
			expectedSub:    "",
		},
		{
			name:           "Single part",
			fqdn:           "localhost",
			expectedDomain: "localhost",
			expectedSub:    "",
		},
		{
			name:           "Empty string",
			fqdn:           "",
			expectedDomain: "",
			expectedSub:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			domain, subname := extractDomainAndSubname(tt.fqdn)
			if domain != tt.expectedDomain {
				t.Errorf("extractDomainAndSubname() domain = %v, want %v", domain, tt.expectedDomain)
			}
			if subname != tt.expectedSub {
				t.Errorf("extractDomainAndSubname() subname = %v, want %v", subname, tt.expectedSub)
			}
		})
	}
}

func TestConvertEndpointToRRSetExtended(t *testing.T) {
	tests := []struct {
		name     string
		input    *endpoint.Endpoint
		expected *desec.RRSet
	}{
		{
			name: "Root domain A record",
			input: &endpoint.Endpoint{
				DNSName:    "example.com",
				RecordType: "A",
				Targets:    endpoint.Targets{"192.0.2.1"},
			},
			expected: &desec.RRSet{
				SubName: "",
				Type:    "A",
				Records: []string{"192.0.2.1"},
				TTL:     3600,
			},
		},
		{
			name: "Multiple targets",
			input: &endpoint.Endpoint{
				DNSName:    "www.example.com",
				RecordType: "A",
				Targets:    endpoint.Targets{"192.0.2.1", "192.0.2.2"},
			},
			expected: &desec.RRSet{
				SubName: "www",
				Type:    "A",
				Records: []string{"192.0.2.1", "192.0.2.2"},
				TTL:     3600,
			},
		},
		{
			name: "CNAME without trailing dot",
			input: &endpoint.Endpoint{
				DNSName:    "www.example.com",
				RecordType: "CNAME",
				Targets:    endpoint.Targets{"alias.example.com"},
			},
			expected: &desec.RRSet{
				SubName: "www",
				Type:    "CNAME",
				Records: []string{"alias.example.com."},
				TTL:     3600,
			},
		},
		{
			name: "CNAME with trailing dot",
			input: &endpoint.Endpoint{
				DNSName:    "www.example.com",
				RecordType: "CNAME",
				Targets:    endpoint.Targets{"alias.example.com."},
			},
			expected: &desec.RRSet{
				SubName: "www",
				Type:    "CNAME",
				Records: []string{"alias.example.com."},
				TTL:     3600,
			},
		},
		{
			name: "TXT record",
			input: &endpoint.Endpoint{
				DNSName:    "_dmarc.example.com",
				RecordType: "TXT",
				Targets:    endpoint.Targets{"v=DMARC1; p=reject"},
			},
			expected: &desec.RRSet{
				SubName: "_dmarc",
				Type:    "TXT",
				Records: []string{"v=DMARC1; p=reject"},
				TTL:     3600,
			},
		},
		{
			name: "A record with TTL lower than minimum",
			input: &endpoint.Endpoint{
				DNSName:    "example.com",
				RecordType: "A",
				Targets:    endpoint.Targets{"192.0.2.1"},
				RecordTTL:  300,
			},
			expected: &desec.RRSet{
				SubName: "",
				Type:    "A",
				Records: []string{"192.0.2.1"},
				TTL:     3600,
			},
		},
		{
			name: "A record with 2-hour TTL",
			input: &endpoint.Endpoint{
				DNSName:    "example.com",
				RecordType: "A",
				Targets:    endpoint.Targets{"192.0.2.1"},
				RecordTTL:  7200,
			},
			expected: &desec.RRSet{
				SubName: "",
				Type:    "A",
				Records: []string{"192.0.2.1"},
				TTL:     7200,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := convertEndpointToRRSet(tt.input, 3600)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("convertEndpointToRRSet() = %+v, want %+v", result, tt.expected)
			}
		})
	}
}

func TestConvertRRSetToEndpointExtended(t *testing.T) {
	tests := []struct {
		name     string
		input    *desec.RRSet
		domain   string
		expected *endpoint.Endpoint
	}{
		{
			name: "Multiple records",
			input: &desec.RRSet{
				SubName: "www",
				Type:    "A",
				Records: []string{"192.0.2.1", "192.0.2.2"},
				TTL:     300,
			},
			domain: "example.com",
			expected: &endpoint.Endpoint{
				DNSName:    "www.example.com.",
				RecordType: "A",
				Targets:    endpoint.Targets{"192.0.2.1", "192.0.2.2"},
				RecordTTL:  300,
			},
		},
		{
			name: "TXT record",
			input: &desec.RRSet{
				SubName: "_dmarc",
				Type:    "TXT",
				Records: []string{"v=DMARC1; p=reject"},
				TTL:     3600,
			},
			domain: "example.com",
			expected: &endpoint.Endpoint{
				DNSName:    "_dmarc.example.com.",
				RecordType: "TXT",
				Targets:    endpoint.Targets{"v=DMARC1; p=reject"},
				RecordTTL:  3600,
			},
		},
		{
			name: "Domain with trailing dot",
			input: &desec.RRSet{
				SubName: "",
				Type:    "A",
				Records: []string{"192.0.2.1"},
				TTL:     300,
			},
			domain: "example.com.",
			expected: &endpoint.Endpoint{
				DNSName:    "example.com.",
				RecordType: "A",
				Targets:    endpoint.Targets{"192.0.2.1"},
				RecordTTL:  300,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := convertRRSetToEndpoint(tt.input, tt.domain)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("convertRRSetToEndpoint() = %+v, want %+v", result, tt.expected)
			}
		})
	}
}

func TestApplyChangesDryRun(t *testing.T) {
	// Test dry run mode
	config := config.Config{
		APIToken:      "test-token",
		DomainFilters: []string{"example.com"},
		DryRun:        true,
	}

	client, err := CreateDesecClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	changes := plan.Changes{
		Create: []*endpoint.Endpoint{
			{
				DNSName:    "test.example.com",
				RecordType: "A",
				Targets:    endpoint.Targets{"192.0.2.1"},
				RecordTTL:  300,
			},
		},
		UpdateNew: []*endpoint.Endpoint{
			{
				DNSName:    "www.example.com",
				RecordType: "A",
				Targets:    endpoint.Targets{"192.0.2.2"},
				RecordTTL:  300,
			},
		},
		Delete: []*endpoint.Endpoint{
			{
				DNSName:    "old.example.com",
				RecordType: "A",
				Targets:    endpoint.Targets{"192.0.2.3"},
				RecordTTL:  300,
			},
		},
	}

	// This should not return an error in dry run mode
	err = client.ApplyChanges(changes)
	if err != nil {
		t.Errorf("ApplyChanges in dry run mode returned error: %v", err)
	}
}

func TestAdjustEndpointsDryRun(t *testing.T) {
	// Test dry run mode
	config := config.Config{
		APIToken:      "test-token",
		DomainFilters: []string{"example.com"},
		DryRun:        true,
	}

	client, err := CreateDesecClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	endpoints := []*endpoint.Endpoint{
		{
			DNSName:    "test.example.com",
			RecordType: "A",
			Targets:    endpoint.Targets{"192.0.2.1"},
			RecordTTL:  300,
		},
	}

	result, err := client.AdjustEndpoints(endpoints)
	if err != nil {
		t.Errorf("AdjustEndpoints in dry run mode returned error: %v", err)
	}

	// In dry run mode, should return the same endpoints
	if !reflect.DeepEqual(result, endpoints) {
		t.Errorf("AdjustEndpoints in dry run mode = %+v, want %+v", result, endpoints)
	}
}
