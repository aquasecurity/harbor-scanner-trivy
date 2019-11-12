package metrics

import (
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/etc"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"net/http"
)

type Server struct {
	cfg    etc.Metrics
	server *http.Server
}

func NewServer(cfg etc.Metrics) *Server {
	mux := http.NewServeMux()
	mux.Handle(cfg.Endpoint, promhttp.Handler())
	return &Server{
		cfg: cfg,
		server: &http.Server{
			Addr:    cfg.Addr,
			Handler: mux,
		},
	}
}

func (s *Server) ListenAndServe() {
	go func() {
		if err := s.listenAndServe(); err != http.ErrServerClosed {
			log.Fatalf("Error: %v", err)
		}
		log.Trace("Metrics server stopped listening for incoming connections")
	}()
}

func (s *Server) listenAndServe() error {
	log.WithField("addr", s.cfg.Addr).Warn("Starting metrics server without TLS")
	return s.server.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) {
	log.Trace("Metrics server shutdown started")
	if err := s.server.Shutdown(ctx); err != nil {
		log.WithError(err).Error("Error while shutting down metrics server")
	}
	log.Trace("Metrics server shutdown completed")
}
