package main

import (
	"github.com/michelangelomo/external-dns-desec-provider/internal/config"
	"github.com/michelangelomo/external-dns-desec-provider/internal/provider"
	"github.com/michelangelomo/external-dns-desec-provider/internal/server"
	log "github.com/sirupsen/logrus"
)

func main() {
	// Load configuration
	config, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("failed to load configuration: %v", err)
	}
	log.WithField("filters", config.DomainFilters).Info("loaded configuration")

	// Init logging
	log.SetLevel(config.LogLevel)

	// Create the desec client
	log.Infof("creating desec client")
	desecClient, err := provider.CreateDesecClient(config)
	if err != nil {
		log.Fatalf("failed to create Desec client: %v", err)
	}

	// Initialize the webhook server
	log.Infof("initializing webhook server on %s", config.GetListeningAddress())
	server := server.NewWebhookServer(desecClient, config)

	// Start the server
	if err := server.Run(config); err != nil {
		log.Fatalf("failed to start server: %v", err)
	}
}
