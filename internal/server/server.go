package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/michelangelomo/external-dns-desec-provider/internal/config"
	"github.com/michelangelomo/external-dns-desec-provider/internal/provider"
	log "github.com/sirupsen/logrus"
	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/plan"
)

type WebhookServer struct {
	httpServer *http.Server
}

type webhook struct {
	desecClient *provider.DesecClient
	config      config.Config
}

const (
	externalDnsWebhookHeader = "application/external.dns.webhook+json;version=1"
)

func NewWebhookServer(desecClient *provider.DesecClient, config config.Config) *WebhookServer {
	var webhook webhook
	webhook.desecClient = desecClient
	webhook.config = config

	mux := mux.NewRouter()
	mux.HandleFunc("/", webhook.negotiateHandler).Methods("GET")
	mux.HandleFunc("/records", webhook.recordsHandler).Methods("GET")
	mux.HandleFunc("/records", webhook.applyChangesHandler).Methods("POST")
	mux.HandleFunc("/adjustendpoints", webhook.adjustEndpointsHandler).Methods("POST")

	mux.Use(NewLogger(LogOptions{EnableStarting: true, Formatter: log.StandardLogger().Formatter}).Middleware)
	mux.Use(externalDnsContentTypeMiddleware)

	return &WebhookServer{
		httpServer: &http.Server{
			Addr:    config.GetListeningAddress(),
			Handler: mux,
		},
	}
}

// Run starts the server in a non-blocking way when called with a goroutine
func (server *WebhookServer) Run(config config.Config) error {
	// The underlying http.Server.ListenAndServe is still blocking
	// but we can now reference the server for graceful shutdown
	return server.httpServer.ListenAndServe()
}

// Shutdown gracefully shuts down the server
func (server *WebhookServer) Shutdown(ctx context.Context) error {
	return server.httpServer.Shutdown(ctx)
}

func externalDnsContentTypeMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", externalDnsWebhookHeader)
		next.ServeHTTP(w, r)
	})
}

func (webhook webhook) negotiateHandler(w http.ResponseWriter, r *http.Request) {
	domainFilter := endpoint.NewDomainFilter(webhook.config.DomainFilters)

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(domainFilter); err != nil {
		log.Errorf("failed to encode domain filter: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	_, _ = w.Write(buf.Bytes())
}

func (webhook webhook) recordsHandler(w http.ResponseWriter, r *http.Request) {
	endpoints := []*endpoint.Endpoint{}

	for _, domain := range webhook.config.DomainFilters {
		domainEndpoints, err := webhook.desecClient.GetEndpoints(domain)
		if err != nil {
			log.Errorf("failed to get records for domain %s: %v", domain, err)
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = fmt.Fprintf(w, "failed to get records for domain %s: %v", domain, err)
			return
		}

		endpoints = append(endpoints, domainEndpoints...)
	}

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(endpoints); err != nil {
		log.Errorf("failed to encode endpoints: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	_, _ = w.Write(buf.Bytes())
}

func (webhook webhook) applyChangesHandler(w http.ResponseWriter, r *http.Request) {
	if err := dumpRequestBodyAtDebug(r, "/records"); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	var changes plan.Changes

	err := json.NewDecoder(r.Body).Decode(&changes)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	err = webhook.desecClient.ApplyChanges(changes)
	if err != nil {
		log.Errorf("failed to apply changes: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (webhook webhook) adjustEndpointsHandler(w http.ResponseWriter, r *http.Request) {
	if err := dumpRequestBodyAtDebug(r, "/adjustendpoints"); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	adjustedEndpoints := []*endpoint.Endpoint{}

	err := json.NewDecoder(r.Body).Decode(&adjustedEndpoints)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	endpoints, err := webhook.desecClient.AdjustEndpoints(adjustedEndpoints)
	if err != nil {
		log.Errorf("failed to adjust endpoints: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	var buf bytes.Buffer
	if err = json.NewEncoder(&buf).Encode(endpoints); err != nil {
		log.Errorf("failed to encode endpoints: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	_, _ = w.Write(buf.Bytes())
}

// dumpRequestBodyAtDebug logs the full request body when debug-level logging
// is enabled, then rewinds r.Body so the handler can decode it normally.
// Used to capture the full plan.Changes payload (including UpdateOld, Labels,
// and ProviderSpecific) that the summary log lines do not show. The body
// read is skipped entirely at info level so production deployments pay no
// extra cost; enable with WEBHOOK_LOGLEVEL=debug.
func dumpRequestBodyAtDebug(r *http.Request, label string) error {
	if !log.IsLevelEnabled(log.DebugLevel) {
		return nil
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Errorf("failed to read %s body for debug log: %v", label, err)
		return err
	}
	log.Debugf("POST %s body: %s", label, string(body))
	r.Body = io.NopCloser(bytes.NewReader(body))
	return nil
}
