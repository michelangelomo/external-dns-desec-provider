package server

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/michelangelomo/external-dns-desec-provider/internal/config"
	"github.com/michelangelomo/external-dns-desec-provider/internal/provider"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
	"sigs.k8s.io/external-dns/endpoint"
)

type WebhookServer struct {
	server *mux.Router
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
	mux.HandleFunc("/healthz", healthzHandler).Methods("GET")
	mux.HandleFunc("/readyz", readyzHandler).Methods("GET")
	mux.HandleFunc("/", webhook.negotiateHandler).Methods("GET")
	mux.HandleFunc("/records", webhook.recordsHandler).Methods("GET")

	mux.Use(NewLogger(LogOptions{EnableStarting: true, Formatter: logrus.StandardLogger().Formatter}).Middleware)
	mux.Use(externalDnsContentTypeMiddleware)

	return &WebhookServer{
		server: mux,
	}
}

func (server *WebhookServer) Run(config config.Config) error {
	return http.ListenAndServe(
		config.GetListeningAddress(),
		server.server,
	)
}

func externalDnsContentTypeMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", externalDnsWebhookHeader)
		next.ServeHTTP(w, r)
	})
}

func (webhook webhook) negotiateHandler(w http.ResponseWriter, r *http.Request) {
	var domainFilter endpoint.DomainFilter
	domainFilter.Filters = webhook.config.DomainFilters

	json.NewEncoder(w).Encode(domainFilter)
}

func (webhook webhook) recordsHandler(w http.ResponseWriter, r *http.Request) {
	endpoints := []*endpoint.Endpoint{}

	for _, domain := range webhook.config.DomainFilters {
		rrset, err := webhook.desecClient.GetRecords(domain)
		log.Debugf("getting records for domain %s", domain)
		log.Debugf("records: %v", rrset)
		if err != nil {
			log.Errorf("failed to get records for domain %s: %v", domain, err.Error())
			continue
		}

		for _, record := range rrset {
			endpoints = append(endpoints, &endpoint.Endpoint{
				DNSName:    record.Name,
				RecordType: record.Type,
				Targets:    record.Records,
				RecordTTL:  endpoint.TTL(record.TTL),
			})
		}
	}

	json.NewEncoder(w).Encode(endpoints)
}
