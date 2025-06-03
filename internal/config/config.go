package config

import (
	"fmt"

	"github.com/kelseyhightower/envconfig"
	log "github.com/sirupsen/logrus"
)

type Config struct {
	APIToken      string   `required:"true"`
	DryRun        bool     `default:"false"`
	DomainFilters []string `required:"true"`
	DefaultTTL    int      `default:"3600"`

	WebhookAddress string `default:"127.0.0.1"`
	WebhookPort    int    `default:"8888"`

	HealthAddress string `default:"0.0.0.0"`
	HealthPort    int    `default:"8080"`

	LogLevel log.Level `default:"info"`
}

func LoadConfig() (Config, error) {
	var config Config

	err := envconfig.Process("webhook", &config)
	if err != nil {
		return config, err
	}

	return config, nil
}

func (config Config) GetListeningAddress() string {
	return fmt.Sprintf("%s:%d", config.WebhookAddress, config.WebhookPort)
}

func (config Config) GetHealthListeningAddress() string {
	return fmt.Sprintf("%s:%d", config.HealthAddress, config.HealthPort)
}
