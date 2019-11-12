package api

import (
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/etc"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"net/http"
)

type Server struct {
	config etc.API
	server *http.Server
}

func NewServer(config etc.API, handler http.Handler) *Server {
	return &Server{
		config: config,
		server: &http.Server{
			Handler:      handler,
			Addr:         config.Addr,
			ReadTimeout:  config.ReadTimeout,
			WriteTimeout: config.WriteTimeout,
			IdleTimeout:  config.IdleTimeout,
		},
	}
}

func (s *Server) ListenAndServe() {
	go func() {
		if err := s.listenAndServe(); err != http.ErrServerClosed {
			log.Fatalf("Error: %v", err)
		}
		log.Trace("API server stopped listening for incoming connections")
	}()
}

func (s *Server) listenAndServe() error {
	if s.config.IsTLSEnabled() {
		log.WithFields(log.Fields{
			"certificate": s.config.TLSCertificate,
			"key":         s.config.TLSKey,
			"addr":        s.config.Addr,
		}).Debug("Starting API server with TLS")
		return s.server.ListenAndServeTLS(s.config.TLSCertificate, s.config.TLSKey)
	}
	log.WithField("addr", s.config.Addr).Warn("Starting API server without TLS")
	return s.server.ListenAndServe()
}

func (s *Server) Shutdown() {
	log.Trace("API server shutdown started")
	if err := s.server.Shutdown(context.Background()); err != nil {
		log.WithError(err).Error("Error while shutting down API server")
	}
	log.Trace("API server shutdown completed")
}
