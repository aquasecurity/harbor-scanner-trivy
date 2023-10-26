package queue

import (
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/gocraft/work"
	"github.com/gomodule/redigo/redis"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/harbor"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/job"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/persistence"
)

const (
	scanArtifactJobName = "scan_artifact"
	scanRequestJobArg   = "scan_request"
)

type Enqueuer interface {
	Enqueue(request harbor.ScanRequest) (job.ScanJob, error)
}

type enqueuer struct {
	enqueuer *work.Enqueuer
	store    persistence.Store
}

func NewEnqueuer(config etc.JobQueue, redisPool *redis.Pool, store persistence.Store) Enqueuer {
	return &enqueuer{
		enqueuer: work.NewEnqueuer(config.Namespace, redisPool),
		store:    store,
	}
}

func (e *enqueuer) Enqueue(request harbor.ScanRequest) (job.ScanJob, error) {
	slog.Debug("Enqueueing scan job")

	b, err := json.Marshal(request)
	if err != nil {
		return job.ScanJob{}, fmt.Errorf("marshalling scan request: %v", err)
	}

	j, err := e.enqueuer.Enqueue(scanArtifactJobName, work.Q{
		scanRequestJobArg: string(b),
	})
	if err != nil {
		return job.ScanJob{}, fmt.Errorf("enqueuing scan artifact job: %v", err)
	}
	slog.Debug("Successfully enqueued scan job", slog.String("job_id", j.ID))

	scanJob := job.ScanJob{
		ID:     j.ID,
		Status: job.Queued,
	}

	if err = e.store.Create(scanJob); err != nil {
		return job.ScanJob{}, fmt.Errorf("creating scan job %v", err)
	}

	return scanJob, nil
}
