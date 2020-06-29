package queue

import (
	"encoding/json"
	"fmt"

	"github.com/gomodule/redigo/redis"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/harbor"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/scan"
	"github.com/gocraft/work"
	log "github.com/sirupsen/logrus"
)

const (
	scanJobDefaultPriority = 1 // The highest
	scanJobMaxFailures     = 1
)

type Worker interface {
	Start()
	Stop()
}

type worker struct {
	workerPool *work.WorkerPool
}

func NewWorker(config etc.JobQueue, redisPool *redis.Pool, controller scan.Controller) Worker {

	workerPool := work.NewWorkerPool(workerContext{}, uint(config.WorkerConcurrency), config.Namespace, redisPool)

	// Note: For each scan job a new instance of the workerContext struct is created.
	// Therefore, the only way to do a proper dependency injection is to use such closure
	// and the following middleware as the first step in the processing chain.
	workerPool.Middleware(func(ctx *workerContext, job *work.Job, next work.NextMiddlewareFunc) error {
		ctx.controller = controller
		return next()
	})

	workerPool.JobWithOptions(scanArtifactJobName,
		work.JobOptions{
			Priority: scanJobDefaultPriority,
			MaxFails: scanJobMaxFailures,
		}, (*workerContext).ScanArtifact)

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

// workerContext is a context for running scan jobs.
type workerContext struct {
	controller scan.Controller
}

// ScanArtifact is a handler function for the specified scan Job with the given workerContext.
func (s *workerContext) ScanArtifact(job *work.Job) (err error) {
	log.WithField("scan_job_id", job.ID).Debug("Executing enqueued scan job")

	request, err := s.unmarshalScanRequest(job)
	if err != nil {
		return
	}

	err = s.controller.Scan(job.ID, request)
	return
}

func (s *workerContext) unmarshalScanRequest(job *work.Job) (request harbor.ScanRequest, err error) {
	// TODO Fail fast and assert that the scan_request arg was set by the enqueuer.
	err = json.Unmarshal([]byte(job.ArgString(scanRequestJobArg)), &request)
	if err != nil {
		return request, fmt.Errorf("unmarshalling scan request: %v", err)
	}
	return
}
