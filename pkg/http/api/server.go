package api

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/etc"
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
				clientCA, err := os.ReadFile(clientCAPath)
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
		if err := s.listenAndServe(); errors.Is(err, http.ErrServerClosed) {
			slog.Error("Error", slog.String("err", err.Error()))
			os.Exit(1)
		}
		slog.Debug("API server stopped listening for incoming connections")
	}()
}

func (s *Server) listenAndServe() error {
	if s.config.IsTLSEnabled() {
		slog.Debug("Starting API server with TLS",
			slog.String("certificate", s.config.TLSCertificate),
			slog.String("key", s.config.TLSKey),
			slog.String("clientCAs", strings.Join(s.config.ClientCAs, ", ")),
			slog.String("addr", s.config.Addr),
		)
		return s.server.ListenAndServeTLS(s.config.TLSCertificate, s.config.TLSKey)
	}
	slog.Warn("Starting API server without TLS", slog.String("addr", s.config.Addr))
	return s.server.ListenAndServe()
}

func (s *Server) Shutdown() {
	slog.Debug("API server shutdown started")
	if err := s.server.Shutdown(context.Background()); err != nil {
		slog.Error("Error while shutting down API server", slog.String("err", err.Error()))
	}
	slog.Debug("API server shutdown completed")
}
