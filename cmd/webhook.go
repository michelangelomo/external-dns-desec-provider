package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/michelangelomo/external-dns-desec-provider/internal/config"
	"github.com/michelangelomo/external-dns-desec-provider/internal/health"
	"github.com/michelangelomo/external-dns-desec-provider/internal/provider"
	"github.com/michelangelomo/external-dns-desec-provider/internal/server"
	log "github.com/sirupsen/logrus"
)

var (
	Version string = "v0.0.0-dev"
)

func main() {
	log.Infof("starting external-dns-desec-provider %s", Version)
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

	// Initialize the health server
	log.Infof("initializing health server on %s", config.GetHealthListeningAddress())
	healthServer := health.NewHealthServer()

	// Create a channel to listen for OS signals
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	// Create error channels for the servers
	webhookErrCh := make(chan error, 1)
	healthErrCh := make(chan error, 1)

	// Start the webhook server in a goroutine
	go func() {
		if err := server.Run(config); err != nil && err != http.ErrServerClosed {
			log.Errorf("webhook server error: %v", err)
			webhookErrCh <- err
		}
	}()

	// Start the health server in a goroutine
	go func() {
		if err := healthServer.Run(config); err != nil && err != http.ErrServerClosed {
			log.Errorf("health server error: %v", err)
			healthErrCh <- err
		}
	}()

	// Wait for a signal to shutdown or for a server error
	select {
	case <-stop:
		log.Info("shutdown signal received")
	case err := <-webhookErrCh:
		log.Errorf("webhook server failed: %v", err)
	case err := <-healthErrCh:
		log.Errorf("health server failed: %v", err)
	}

	// Create a timeout context for shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Gracefully shutdown both servers
	if err := server.Shutdown(ctx); err != nil {
		log.Errorf("webhook server shutdown error: %v", err)
	}

	if err := healthServer.Shutdown(ctx); err != nil {
		log.Errorf("health server shutdown error: %v", err)
	}

	log.Info("servers shutdown completed")
}
