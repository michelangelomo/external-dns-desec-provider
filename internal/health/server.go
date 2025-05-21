package health

import (
	"context"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/michelangelomo/external-dns-desec-provider/internal/config"
)

type HealthServer struct {
	httpServer *http.Server
}

func NewHealthServer() *HealthServer {
	mux := mux.NewRouter()
	mux.HandleFunc("/healthz", healthzHandler).Methods("GET")
	mux.HandleFunc("/readyz", readyzHandler).Methods("GET")

	return &HealthServer{
		httpServer: &http.Server{
			Handler: mux,
		},
	}
}

func (server *HealthServer) Run(config config.Config) error {
	server.httpServer.Addr = config.GetHealthListeningAddress()
	return server.httpServer.ListenAndServe()
}

// Shutdown gracefully shuts down the server
func (server *HealthServer) Shutdown(ctx context.Context) error {
	if server.httpServer != nil {
		return server.httpServer.Shutdown(ctx)
	}
	return nil
}

func healthzHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func readyzHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}
