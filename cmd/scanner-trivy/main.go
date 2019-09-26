package main

import (
	"context"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/http/api/v1"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/queue"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/store/redis"
	log "github.com/sirupsen/logrus"
	"net/http"
	"os"
	"os/signal"
)

func main() {
	log.SetOutput(os.Stdout)
	log.SetLevel(log.DebugLevel)
	log.SetReportCaller(false)
	log.SetFormatter(&log.JSONFormatter{})

	log.Info("Starting harbor-scanner-trivy")

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

	server := &http.Server{
		Handler:      apiHandler,
		Addr:         apiConfig.Addr,
		ReadTimeout:  apiConfig.ReadTimeout,
		WriteTimeout: apiConfig.WriteTimeout,
	}

	shutdownComplete := make(chan struct{})
	go func() {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, os.Interrupt, os.Kill)
		captured := <-sigint
		log.Debugf("Trapped os signal %v", captured)

		log.Debug("Graceful shutdown started")
		if err := server.Shutdown(context.Background()); err != nil {
			log.WithError(err).Error("Error while shutting down server")
		}
		log.Debug("Graceful shutdown completed")

		log.Debug("Stopping worker started")
		worker.Stop()
		log.Debug("Stopping worker completed")
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
