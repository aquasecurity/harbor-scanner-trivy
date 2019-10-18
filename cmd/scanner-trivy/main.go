package main

import (
	"context"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/http/api"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/http/api/v1"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/queue"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/store/redis"
	log "github.com/sirupsen/logrus"
	"net/http"
	"os"
	"os/signal"
)

var (
	// Default wise GoReleaser sets three ldflags:
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	log.SetOutput(os.Stdout)
	log.SetLevel(etc.GetLogLevel())
	log.SetReportCaller(false)
	log.SetFormatter(&log.JSONFormatter{})

	log.WithFields(log.Fields{
		"version":  version,
		"commit":   commit,
		"built_at": date,
	}).Info("Starting harbor-scanner-trivy")

	jobQueueConfig, err := etc.GetJobQueueConfig()
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
	log.Debugf("Job queue config %v", jobQueueConfig)

	worker := queue.NewWorker(jobQueueConfig)

	apiConfig, err := etc.GetAPIConfig()
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
	log.Debugf("API server config: %v", apiConfig)

	apiHandler, err := newAPIHandler(jobQueueConfig)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	server := api.NewServer(apiConfig, apiHandler)

	shutdownComplete := make(chan struct{})
	go func() {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, os.Interrupt, os.Kill)
		captured := <-sigint
		log.WithField("signal", captured.String()).Debug("Trapped os signal")

		log.Debug("API server shutdown started")
		if err := server.Shutdown(context.Background()); err != nil {
			log.WithError(err).Error("Error while shutting down server")
		}
		log.Debug("API server shutdown completed")

		log.Debug("Job queue shutdown started")
		worker.Stop()
		log.Debug("Job queue shutdown completed")
		close(shutdownComplete)
	}()

	worker.Start()

	go func() {
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatalf("Error: %v", err)
		}
		log.Debug("ListenAndServe returned")
	}()
	<-shutdownComplete
}

func newAPIHandler(jobQueueConfig etc.JobQueueConfig) (apiHandler http.Handler, err error) {
	storeConfig, err := etc.GetRedisStoreConfig()
	if err != nil {
		return nil, err
	}
	log.Debugf("Redis store config: %v", storeConfig)

	dataStore := redis.NewDataStore(storeConfig)
	enqueuer := queue.NewEnqueuer(jobQueueConfig, dataStore)

	apiHandler = v1.NewAPIHandler(enqueuer, dataStore)
	return
}
