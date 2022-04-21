package api

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/etc"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/context"
)

type Server struct {
	config etc.API
	server *http.Server
}

func NewServer(config etc.API, handler http.Handler) (server *Server, err error) {
	server = &Server{
		config: config,
		server: &http.Server{
			Handler:      handler,
			Addr:         config.Addr,
			ReadTimeout:  config.ReadTimeout,
			WriteTimeout: config.WriteTimeout,
			IdleTimeout:  config.IdleTimeout,
		},
	}

	if config.IsTLSEnabled() {
		server.server.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			// The API server prefers elliptic curves which have assembly implementations
			// to ensure performance under heavy loads.
			CurvePreferences: []tls.CurveID{
				tls.X25519,
				tls.CurveP256,
			},
			// The API server only supports cipher suites which use ECDHE (forward secrecy)
			// and does not support weak cipher suites that use RC4, 3DES or CBC.
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
		}

		if len(config.ClientCAs) > 0 {
			certPool := x509.NewCertPool()

			for _, clientCAPath := range config.ClientCAs {
				clientCA, err := ioutil.ReadFile(clientCAPath)
				if err != nil {
					return nil, fmt.Errorf("cound not read file %s: %w", clientCAPath, err)
				}

				certPool.AppendCertsFromPEM(clientCA)
			}

			server.server.TLSConfig.ClientCAs = certPool
			server.server.TLSConfig.ClientAuth = tls.RequireAndVerifyClientCert
		}
	}

	return
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
			"clientCAs":   strings.Join(s.config.ClientCAs, ", "),
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
