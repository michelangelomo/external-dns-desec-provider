package provider

import (
	"reflect"
	"testing"

	"github.com/nrdcg/desec"
	"sigs.k8s.io/external-dns/endpoint"
)

func TestConvertEndpointToRRSet(t *testing.T) {
	tests := []struct {
		name     string
		input    *endpoint.Endpoint
		expected *desec.RRSet
	}{
		{
			name: "Valid A record",
			input: &endpoint.Endpoint{
				DNSName:    "www.example.com",
				RecordType: "A",
				Targets:    endpoint.Targets{"192.0.2.1"},
				RecordTTL:  300,
			},
			expected: &desec.RRSet{
				SubName: "www",
				Type:    "A",
				Records: []string{"192.0.2.1"},
				TTL:     300,
			},
		},
		{
			name: "Valid CNAME record",
			input: &endpoint.Endpoint{
				DNSName:    "www.example.com",
				RecordType: "CNAME",
				Targets:    endpoint.Targets{"test.example.com"},
				RecordTTL:  300,
			},
			expected: &desec.RRSet{
				SubName: "www",
				Type:    "CNAME",
				Records: []string{"test.example.com."},
				TTL:     300,
			},
		},
		{
			name:     "Nil input",
			input:    nil,
			expected: nil,
		},
		{
			name: "Empty targets",
			input: &endpoint.Endpoint{
				DNSName:    "example.com",
				RecordType: "A",
				Targets:    endpoint.Targets{},
				RecordTTL:  3600,
			},
			expected: &desec.RRSet{
				SubName: "",
				Type:    "A",
				Records: []string{},
				TTL:     3600,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := convertEndpointToRRSet(tt.input)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("convertEndpointToRRSet() = %+v, want %+v", result, tt.expected)
			}
		})
	}
}

func TestConvertRRSetToEndpoint(t *testing.T) {
	tests := []struct {
		name     string
		input    *desec.RRSet
		domain   string
		expected *endpoint.Endpoint
	}{
		{
			name: "Valid record",
			input: &desec.RRSet{
				SubName: "api",
				Type:    "A",
				Records: []string{"192.0.2.2"},
				TTL:     600,
			},
			domain: "example.com",
			expected: &endpoint.Endpoint{
				DNSName:    "api.example.com.",
				RecordType: "A",
				Targets:    endpoint.Targets{"192.0.2.2"},
				RecordTTL:  600,
			},
		},
		{
			name: "Root domain",
			input: &desec.RRSet{
				SubName: "",
				Type:    "A",
				Records: []string{"192.0.2.3"},
				TTL:     120,
			},
			domain: "example.com",
			expected: &endpoint.Endpoint{
				DNSName:    "example.com.",
				RecordType: "A",
				Targets:    endpoint.Targets{"192.0.2.3"},
				RecordTTL:  120,
			},
		},
		{
			name:     "Nil input",
			input:    nil,
			domain:   "example.com",
			expected: nil,
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
