package main

import (
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/http/api"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/http/api/v1"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/persistence/redis"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/queue"
	log "github.com/sirupsen/logrus"
	"os"
	"os/signal"
	"syscall"
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

	config, err := etc.GetConfig()
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	worker := queue.NewWorker(config.JobQueue)
	apiServer := newAPIServer(config)

	shutdownComplete := make(chan struct{})
	go func() {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, syscall.SIGINT, syscall.SIGTERM)
		captured := <-sigint
		log.WithField("signal", captured.String()).Debug("Trapped os signal")

		apiServer.Shutdown()
		worker.Stop()

		close(shutdownComplete)
	}()

	worker.Start()
	apiServer.ListenAndServe()

	<-shutdownComplete
}

func newAPIServer(config etc.Config) *api.Server {
	store := redis.NewStore(config.RedisStore)
	enqueuer := queue.NewEnqueuer(config.JobQueue, store)
	apiHandler := v1.NewAPIHandler(enqueuer, store)
	return api.NewServer(config.API, apiHandler)
}
