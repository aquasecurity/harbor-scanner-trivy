package main

import (
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	log "github.com/sirupsen/logrus"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/ext"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/http/api"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/http/api/v1"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/persistence"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/persistence/redis"
	rethinkdb2 "github.com/aquasecurity/harbor-scanner-trivy/pkg/persistence/rethinkdb"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/queue"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/queue/rethinkdb"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/scan"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/trivy"
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
		return fmt.Errorf("getting config: %w", err)
	}
	if err = etc.Check(config); err != nil {
		return fmt.Errorf("checking config: %w", err)
	}

	var (
		store persistence.Store
		worker queue.Worker
		enqueuer queue.Enqueuer
	)

	switch strings.ToLower(config.DatabaseType) {
	case "redis":
		store, worker, enqueuer = setupRedis(config)
	case "rethinkdb":
		store, worker, enqueuer = setupRethinkDb(config)
	default:
		return fmt.Errorf("invalid database type %s", config.DatabaseType)
	}

	apiHandler := v1.NewAPIHandler(info, config, enqueuer, store, trivy.NewWrapper(config.Trivy, ext.DefaultAmbassador))
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

func setupRedis(config etc.Config) (persistence.Store, queue.Worker, queue.Enqueuer) {
	worker := queue.NewWorker(config.JobQueue)
	store := redis.NewStore(config.RedisStore)
	enqueuer := queue.NewEnqueuer(config.JobQueue, store)

	return store, worker, enqueuer
}

func setupRethinkDb(config etc.Config) (persistence.Store, queue.Worker, queue.Enqueuer) {
	db, err := etc.GetRethinkdbConnection(config.Rethink)
	if err != nil {
		log.WithError(err).Fatalln("connection to rethinkdb failed")
	}

	wrapper := trivy.NewWrapper(config.Trivy, ext.DefaultAmbassador)
	store := rethinkdb2.NewStore(db, config.Rethink)
	controller := scan.NewController(store, wrapper, scan.NewTransformer(&scan.SystemClock{}))
	enqueuer := rethinkdb.NewEnqueuer(db, store, config.Rethink)
	worker := rethinkdb.NewWorkerPool(db, controller, config.Rethink)

	return store, worker, enqueuer
}
