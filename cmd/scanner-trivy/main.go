package main

import (
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/http/api"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/http/api/v1"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/persistence/redis"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/queue"
	log "github.com/sirupsen/logrus"
	"golang.org/x/xerrors"
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

	info := etc.BuildInfo{
		Version: version,
		Commit:  commit,
		Date:    date,
	}

	if err := run(info); err != nil {
		log.Fatalf("Error: %v", err)
	}
}

func run(info etc.BuildInfo) error {
	log.WithFields(log.Fields{
		"version":  info.Version,
		"commit":   info.Commit,
		"built_at": info.Date,
	}).Info("Starting harbor-scanner-trivy")

	config, err := etc.GetConfig()
	if err != nil {
		return xerrors.Errorf("getting config: %w", err)
	}

	worker := queue.NewWorker(config.JobQueue)

	store := redis.NewStore(config.RedisStore)
	enqueuer := queue.NewEnqueuer(config.JobQueue, store)
	apiHandler := v1.NewAPIHandler(info, enqueuer, store)
	apiServer := api.NewServer(config.API, apiHandler)

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
	return nil
}
