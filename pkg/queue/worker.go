package queue

import (
	"encoding/json"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/model"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/model/harbor"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/scan"
	store "github.com/aquasecurity/harbor-scanner-trivy/pkg/store/redis"
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

func NewWorker(config etc.JobQueueConfig) Worker {
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
	w.workerPool.Stop()
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
	config, err := etc.GetWrapperConfig()
	if err != nil {
		return controller, err
	}
	wrapper := trivy.NewWrapper(config)

	storeConfig, err := etc.GetRedisStoreConfig()
	if err != nil {
		return controller, err
	}
	dataStore := store.NewDataStore(storeConfig)

	controller = scan.NewController(dataStore, wrapper, model.NewTransformer())
	return
}

func (s *workerContext) unmarshalScanRequest(job *work.Job) (request harbor.ScanRequest, err error) {
	err = json.Unmarshal([]byte(job.ArgString(scanRequestJobArg)), &request)
	if err != nil {
		return request, xerrors.Errorf("unmarshalling scan request: %v", err)
	}
	return
}
