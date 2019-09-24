package main

import (
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/http/api/v1"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/image/trivy"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/queue"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/store/redis"
	log "github.com/sirupsen/logrus"
	"net/http"
	"os"
)

func main() {
	log.SetOutput(os.Stdout)
	log.SetLevel(log.DebugLevel)
	log.SetReportCaller(false)
	log.SetFormatter(&log.JSONFormatter{})

	log.Info("Starting harbor-scanner-trivy")

	apiConfig, err := etc.GetAPIConfig()
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
	log.Debugf("API server config: %v", apiConfig)

	apiHandler, err := newAPIHandler()
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	server := &http.Server{
		Handler:      apiHandler,
		Addr:         apiConfig.Addr,
		ReadTimeout:  apiConfig.ReadTimeout,
		WriteTimeout: apiConfig.WriteTimeout,
	}
	err = server.ListenAndServe()

	if err != nil && err != http.ErrServerClosed {
		log.Fatalf("Error: %v", err)
	}
}

func newAPIHandler() (apiHandler http.Handler, err error) {
	cfg, err := etc.GetConfig()
	if err != nil {
		return nil, err
	}

	scanner, err := trivy.NewScanner(cfg)
	if err != nil {
		return nil, err
	}

	storeConfig, err := etc.GetRedisStoreConfig()
	if err != nil {
		return nil, err
	}
	log.Debugf("Redis store config: %v", storeConfig)

	dataStore := redis.NewDataStore(storeConfig)

	jobQueueConfig, err := etc.GetJobQueueConfig()
	if err != nil {
		return nil, err
	}
	log.Debugf("Job queue config %v", jobQueueConfig)

	enqueuer := queue.NewEnqueuer(jobQueueConfig, dataStore)
	apiHandler = v1.NewAPIHandler(scanner, enqueuer)
	return
}
