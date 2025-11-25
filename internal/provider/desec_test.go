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
		name          string
		domainFilters []string
		endpoints     []*endpoint.Endpoint
		expected      map[string][]*endpoint.Endpoint
	}{
		{
			name:          "Single domain",
			domainFilters: []string{"example.com"},
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
			name:          "Multiple domains",
			domainFilters: []string{"example.com", "test.org"},
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
			name:          "With trailing dot",
			domainFilters: []string{"example.com"},
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
			name:          "Empty endpoints",
			domainFilters: []string{"example.com"},
			endpoints:     []*endpoint.Endpoint{},
			expected:      map[string][]*endpoint.Endpoint{},
		},
		{
			name:          "Nil endpoint",
			domainFilters: []string{"example.com"},
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
			name:          "Empty DNS name",
			domainFilters: []string{"example.com"},
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
		{
			name:          "Subdomain matching",
			domainFilters: []string{"foo.example.com", "bar.example.com"},
			endpoints: []*endpoint.Endpoint{
				{
					DNSName:    "foo.foo.example.com",
					RecordType: "A",
					Targets:    endpoint.Targets{"192.0.2.1"},
				},
				{
					DNSName:    "foo.bar.example.com",
					RecordType: "A",
					Targets:    endpoint.Targets{"192.0.2.2"},
				},
			},
			expected: map[string][]*endpoint.Endpoint{
				"foo.example.com": {
					{
						DNSName:    "foo.foo.example.com",
						RecordType: "A",
						Targets:    endpoint.Targets{"192.0.2.1"},
					},
				},
				"bar.example.com": {
					{
						DNSName:    "foo.bar.example.com",
						RecordType: "A",
						Targets:    endpoint.Targets{"192.0.2.2"},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &DesecClient{
				domainFilters: tt.domainFilters,
			}
			result := client.mapEndpointsByHostname(tt.endpoints)
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
		expectError    bool
	}{
		{
			name:           "Standard subdomain",
			fqdn:           "www.example.com",
			expectedDomain: "example.com",
			expectedSub:    "www",
			expectError:    false,
		},
		{
			name:           "Deep subdomain",
			fqdn:           "api.v1.example.com",
			expectedDomain: "example.com",
			expectedSub:    "api.v1",
			expectError:    false,
		},
		{
			name:           "Root domain",
			fqdn:           "example.com",
			expectedDomain: "example.com",
			expectedSub:    "",
			expectError:    false,
		},
		{
			name:           "Single part",
			fqdn:           "localhost",
			expectedDomain: "",
			expectedSub:    "",
			expectError:    true,
		},
		{
			name:           "Empty string",
			fqdn:           "",
			expectedDomain: "",
			expectedSub:    "",
			expectError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			domain, subname, err := extractDomainAndSubname(tt.fqdn)
			if tt.expectError && err == nil {
				t.Errorf("extractDomainAndSubname() expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("extractDomainAndSubname() unexpected error = %v", err)
			}
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
		domain   string
		expected *desec.RRSet
	}{
		{
			name: "Root domain A record",
			input: &endpoint.Endpoint{
				DNSName:    "example.com",
				RecordType: "A",
				Targets:    endpoint.Targets{"192.0.2.1"},
			},
			domain: "example.com",
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
			domain: "example.com",
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
			domain: "example.com",
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
			domain: "example.com",
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
			domain: "example.com",
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
			domain: "example.com",
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
			domain: "example.com",
			expected: &desec.RRSet{
				SubName: "",
				Type:    "A",
				Records: []string{"192.0.2.1"},
				TTL:     7200,
			},
		},
		{
			name: "Subdomain with longer domain filter",
			input: &endpoint.Endpoint{
				DNSName:    "foo.foo.example.com",
				RecordType: "A",
				Targets:    endpoint.Targets{"192.0.2.1"},
			},
			domain: "foo.example.com",
			expected: &desec.RRSet{
				SubName: "foo",
				Type:    "A",
				Records: []string{"192.0.2.1"},
				TTL:     3600,
			},
		},
		{
			name: "Subdomain with apex domain filter",
			input: &endpoint.Endpoint{
				DNSName:    "bar.example.com",
				RecordType: "A",
				Targets:    endpoint.Targets{"192.0.2.2"},
			},
			domain: "example.com",
			expected: &desec.RRSet{
				SubName: "bar",
				Type:    "A",
				Records: []string{"192.0.2.2"},
				TTL:     3600,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := convertEndpointToRRSet(tt.input, tt.domain, 3600)
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

func TestSubDomainScenarios(t *testing.T) {
	tests := []struct {
		name          string
		domainFilters []string
		endpoints     []*endpoint.Endpoint
		expected      map[string][]*endpoint.Endpoint
	}{
		{
			name:          "Single domain with multi-level subdomain",
			domainFilters: []string{"example.com"},
			endpoints: []*endpoint.Endpoint{
				{
					DNSName:    "foo.bar.example.com",
					RecordType: "A",
					Targets:    endpoint.Targets{"192.0.2.1"},
				},
			},
			expected: map[string][]*endpoint.Endpoint{
				"example.com": {
					{
						DNSName:    "foo.bar.example.com",
						RecordType: "A",
						Targets:    endpoint.Targets{"192.0.2.1"},
					},
				},
			},
		},
		{
			name:          "Subdomain zone separate from parent",
			domainFilters: []string{"bar.example.org"},
			endpoints: []*endpoint.Endpoint{
				{
					DNSName:    "foo.bar.example.org",
					RecordType: "A",
					Targets:    endpoint.Targets{"192.0.2.1"},
				},
			},
			expected: map[string][]*endpoint.Endpoint{
				"bar.example.org": {
					{
						DNSName:    "foo.bar.example.org",
						RecordType: "A",
						Targets:    endpoint.Targets{"192.0.2.1"},
					},
				},
			},
		},
		{
			name:          "Multiple zones with correct routing",
			domainFilters: []string{"example.com", "bar.example.org"},
			endpoints: []*endpoint.Endpoint{
				{
					DNSName:    "foo.bar.example.com",
					RecordType: "A",
					Targets:    endpoint.Targets{"192.0.2.1"},
				},
				{
					DNSName:    "foo.bar.example.org",
					RecordType: "A",
					Targets:    endpoint.Targets{"192.0.2.2"},
				},
				{
					DNSName:    "www.example.com",
					RecordType: "A",
					Targets:    endpoint.Targets{"192.0.2.3"},
				},
			},
			expected: map[string][]*endpoint.Endpoint{
				"example.com": {
					{
						DNSName:    "foo.bar.example.com",
						RecordType: "A",
						Targets:    endpoint.Targets{"192.0.2.1"},
					},
					{
						DNSName:    "www.example.com",
						RecordType: "A",
						Targets:    endpoint.Targets{"192.0.2.3"},
					},
				},
				"bar.example.org": {
					{
						DNSName:    "foo.bar.example.org",
						RecordType: "A",
						Targets:    endpoint.Targets{"192.0.2.2"},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &DesecClient{
				domainFilters: tt.domainFilters,
			}
			result := client.mapEndpointsByHostname(tt.endpoints)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("mapEndpointsByHostname() = %+v, want %+v", result, tt.expected)
			}
		})
	}
}

func TestSubDomainConvertEndpointToRRSet(t *testing.T) {
	tests := []struct {
		name     string
		input    *endpoint.Endpoint
		domain   string
		expected *desec.RRSet
	}{
		{
			name: "Multi-level subdomain in example.com",
			input: &endpoint.Endpoint{
				DNSName:    "foo.bar.example.com",
				RecordType: "A",
				Targets:    endpoint.Targets{"192.0.2.1"},
			},
			domain: "example.com",
			expected: &desec.RRSet{
				SubName: "foo.bar",
				Type:    "A",
				Records: []string{"192.0.2.1"},
				TTL:     3600,
			},
		},
		{
			name: "Single subdomain in bar.example.org zone",
			input: &endpoint.Endpoint{
				DNSName:    "foo.bar.example.org",
				RecordType: "A",
				Targets:    endpoint.Targets{"192.0.2.1"},
			},
			domain: "bar.example.org",
			expected: &desec.RRSet{
				SubName: "foo",
				Type:    "A",
				Records: []string{"192.0.2.1"},
				TTL:     3600,
			},
		},
		{
			name: "Apex record in subdomain zone",
			input: &endpoint.Endpoint{
				DNSName:    "bar.example.org",
				RecordType: "A",
				Targets:    endpoint.Targets{"192.0.2.1"},
			},
			domain: "bar.example.org",
			expected: &desec.RRSet{
				SubName: "",
				Type:    "A",
				Records: []string{"192.0.2.1"},
				TTL:     3600,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := convertEndpointToRRSet(tt.input, tt.domain, 3600)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("convertEndpointToRRSet() = %+v, want %+v", result, tt.expected)
			}
		})
	}
}
