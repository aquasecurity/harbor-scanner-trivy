package api

import (
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/etc"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"net/http"
)

type Server struct {
	config etc.APIConfig
	server *http.Server
}

func NewServer(config etc.APIConfig, handler http.Handler) *Server {
	return &Server{
		config: config,
		server: &http.Server{
			Handler:      handler,
			Addr:         config.Addr,
			ReadTimeout:  config.ReadTimeout,
			WriteTimeout: config.WriteTimeout,
		},
	}
}

func (s *Server) ListenAndServe() error {
	if s.config.IsTLSEnabled() {
		log.WithFields(log.Fields{
			"certificate": s.config.TLSCertificate,
			"key":         s.config.TLSKey,
		}).Debug("Starting API server with TLS")
		return s.server.ListenAndServeTLS(s.config.TLSCertificate, s.config.TLSKey)
	}
	log.Warn("Starting API server without TLS")
	return s.server.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.server.Shutdown(ctx)
}
