package config

import (
	"os"
	"testing"

	log "github.com/sirupsen/logrus"
)

func TestLoadConfig(t *testing.T) {
	tests := []struct {
		name        string
		envVars     map[string]string
		expectError bool
		expected    Config
	}{
		{
			name: "Valid configuration",
			envVars: map[string]string{
				"WEBHOOK_APITOKEN":       "test-token",
				"WEBHOOK_DOMAINFILTERS":  "example.com,test.org",
				"WEBHOOK_DRYRUN":         "true",
				"WEBHOOK_WEBHOOKADDRESS": "0.0.0.0",
				"WEBHOOK_WEBHOOKPORT":    "9000",
				"WEBHOOK_HEALTHADDRESS":  "127.0.0.1",
				"WEBHOOK_HEALTHPORT":     "9001",
				"WEBHOOK_LOGLEVEL":       "debug",
			},
			expectError: false,
			expected: Config{
				APIToken:       "test-token",
				DomainFilters:  []string{"example.com", "test.org"},
				DryRun:         true,
				WebhookAddress: "0.0.0.0",
				WebhookPort:    9000,
				HealthAddress:  "127.0.0.1",
				HealthPort:     9001,
				LogLevel:       log.DebugLevel,
			},
		},
		{
			name: "Minimal valid configuration",
			envVars: map[string]string{
				"WEBHOOK_APITOKEN":      "minimal-token",
				"WEBHOOK_DOMAINFILTERS": "minimal.com",
			},
			expectError: false,
			expected: Config{
				APIToken:       "minimal-token",
				DomainFilters:  []string{"minimal.com"},
				DryRun:         false,
				WebhookAddress: "127.0.0.1",
				WebhookPort:    8888,
				HealthAddress:  "0.0.0.0",
				HealthPort:     8080,
				LogLevel:       log.InfoLevel,
			},
		},
		{
			name: "Missing API token",
			envVars: map[string]string{
				"WEBHOOK_DOMAINFILTERS": "example.com",
			},
			expectError: true,
		},
		{
			name: "Missing domain filters",
			envVars: map[string]string{
				"WEBHOOK_APITOKEN": "test-token",
			},
			expectError: true,
		},
		{
			name:        "No environment variables",
			envVars:     map[string]string{},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear environment
			clearWebhookEnvVars()

			// Set test environment variables
			for key, value := range tt.envVars {
				os.Setenv(key, value)
			}

			config, err := LoadConfig()

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			// Compare configuration
			if config.APIToken != tt.expected.APIToken {
				t.Errorf("APIToken = %v, want %v", config.APIToken, tt.expected.APIToken)
			}
			if len(config.DomainFilters) != len(tt.expected.DomainFilters) {
				t.Errorf("DomainFilters length = %v, want %v", len(config.DomainFilters), len(tt.expected.DomainFilters))
			} else {
				for i, filter := range config.DomainFilters {
					if filter != tt.expected.DomainFilters[i] {
						t.Errorf("DomainFilters[%d] = %v, want %v", i, filter, tt.expected.DomainFilters[i])
					}
				}
			}
			if config.DryRun != tt.expected.DryRun {
				t.Errorf("DryRun = %v, want %v", config.DryRun, tt.expected.DryRun)
			}
			if config.WebhookAddress != tt.expected.WebhookAddress {
				t.Errorf("WebhookAddress = %v, want %v", config.WebhookAddress, tt.expected.WebhookAddress)
			}
			if config.WebhookPort != tt.expected.WebhookPort {
				t.Errorf("WebhookPort = %v, want %v", config.WebhookPort, tt.expected.WebhookPort)
			}
			if config.HealthAddress != tt.expected.HealthAddress {
				t.Errorf("HealthAddress = %v, want %v", config.HealthAddress, tt.expected.HealthAddress)
			}
			if config.HealthPort != tt.expected.HealthPort {
				t.Errorf("HealthPort = %v, want %v", config.HealthPort, tt.expected.HealthPort)
			}
			if config.LogLevel != tt.expected.LogLevel {
				t.Errorf("LogLevel = %v, want %v", config.LogLevel, tt.expected.LogLevel)
			}
		})
	}

	// Clean up
	clearWebhookEnvVars()
}

func TestGetListeningAddress(t *testing.T) {
	tests := []struct {
		name     string
		config   Config
		expected string
	}{
		{
			name: "Default configuration",
			config: Config{
				WebhookAddress: "127.0.0.1",
				WebhookPort:    8888,
			},
			expected: "127.0.0.1:8888",
		},
		{
			name: "Custom configuration",
			config: Config{
				WebhookAddress: "0.0.0.0",
				WebhookPort:    9000,
			},
			expected: "0.0.0.0:9000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.GetListeningAddress()
			if result != tt.expected {
				t.Errorf("GetListeningAddress() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestGetHealthListeningAddress(t *testing.T) {
	tests := []struct {
		name     string
		config   Config
		expected string
	}{
		{
			name: "Default configuration",
			config: Config{
				HealthAddress: "0.0.0.0",
				HealthPort:    8080,
			},
			expected: "0.0.0.0:8080",
		},
		{
			name: "Custom configuration",
			config: Config{
				HealthAddress: "127.0.0.1",
				HealthPort:    9001,
			},
			expected: "127.0.0.1:9001",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.GetHealthListeningAddress()
			if result != tt.expected {
				t.Errorf("GetHealthListeningAddress() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func clearWebhookEnvVars() {
	envVars := []string{
		"WEBHOOK_APITOKEN",
		"WEBHOOK_DRYRUN",
		"WEBHOOK_DOMAINFILTERS",
		"WEBHOOK_WEBHOOKADDRESS",
		"WEBHOOK_WEBHOOKPORT",
		"WEBHOOK_HEALTHADDRESS",
		"WEBHOOK_HEALTHPORT",
		"WEBHOOK_LOGLEVEL",
	}

	for _, envVar := range envVars {
		os.Unsetenv(envVar)
	}
}
