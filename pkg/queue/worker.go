package queue

import (
	"encoding/json"
	"os"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/ext"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/harbor"
	store "github.com/aquasecurity/harbor-scanner-trivy/pkg/persistence/redis"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/scan"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/trivy"
	"github.com/gocraft/work"
	"github.com/gomodule/redigo/redis"
	log "github.com/sirupsen/logrus"
	"golang.org/x/xerrors"
)

type Worker interface {
	Start()
	Stop()
}

type worker struct {
	workerPool *work.WorkerPool
}

func NewWorker(config etc.JobQueue) Worker {
	redisPool := &redis.Pool{
		MaxActive: config.PoolMaxActive,
		MaxIdle:   config.PoolMaxIdle,
		Wait:      true,
		Dial: func() (redis.Conn, error) {
			return redis.DialURL(config.RedisURL)
		},
	}
	workerPool := work.NewWorkerPool(workerContext{}, uint(config.WorkerConcurrency), config.Namespace, redisPool)

	workerPool.JobWithOptions(scanArtifactJobName, work.JobOptions{Priority: 1, MaxFails: 1}, (*workerContext).ScanArtifact)

	return &worker{
		workerPool: workerPool,
	}
}

func (w *worker) Start() {
	w.workerPool.Start()
}

func (w *worker) Stop() {
	log.Trace("Job queue shutdown started")
	w.workerPool.Stop()
	log.Trace("Job queue shutdown completed")
}

type workerContext struct {
}

func (s *workerContext) ScanArtifact(job *work.Job) (err error) {
	log.WithField("scan_job_id", job.ID).Debug("Executing enqueued scan job")

	controller, err := s.controller()
	if err != nil {
		return
	}

	request, err := s.unmarshalScanRequest(job)
	if err != nil {
		return
	}

	err = controller.Scan(job.ID, request)
	return
}

func (s *workerContext) controller() (controller scan.Controller, err error) {
	config, err := etc.GetConfig()
	if err != nil {
		return nil, err
	}

	if _, err := os.Stat(config.Trivy.ReportsDir); os.IsNotExist(err) {
		log.WithField("path", config.Trivy.ReportsDir).Debug("Creating reports dir")
		err = os.MkdirAll(config.Trivy.ReportsDir, os.ModePerm)
		if err != nil {
			return nil, err
		}
	}

	wrapper := trivy.NewWrapper(config.Trivy, ext.DefaultAmbassador)
	dataStore := store.NewStore(config.RedisStore)

	controller = scan.NewController(dataStore, wrapper, scan.NewTransformer(&scan.SystemClock{}))
	return
}

func (s *workerContext) unmarshalScanRequest(job *work.Job) (request harbor.ScanRequest, err error) {
	err = json.Unmarshal([]byte(job.ArgString(scanRequestJobArg)), &request)
	if err != nil {
		return request, xerrors.Errorf("unmarshalling scan request: %v", err)
	}
	return
}
