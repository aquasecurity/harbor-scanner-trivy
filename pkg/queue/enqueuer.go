package queue

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"

	"github.com/redis/go-redis/v9"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/harbor"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/job"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/persistence"
)

const scanArtifactJobName = "scan_artifact"

type Enqueuer interface {
	Enqueue(ctx context.Context, request harbor.ScanRequest) (job.ScanJob, error)
}

type enqueuer struct {
	namespace string
	rdb       *redis.Client
	store     persistence.Store
}

type Job struct {
	Name string
	ID   string
	Args Args
}

type Args struct {
	ScanRequest *harbor.ScanRequest `json:",omitempty"`
}

func NewEnqueuer(config etc.JobQueue, rdb *redis.Client, store persistence.Store) Enqueuer {
	return &enqueuer{
		namespace: config.Namespace,
		rdb:       rdb,
		store:     store,
	}
}

func (e *enqueuer) Enqueue(ctx context.Context, request harbor.ScanRequest) (job.ScanJob, error) {
	slog.Debug("Enqueueing scan job")
	j := Job{
		Name: scanArtifactJobName,
		ID:   makeIdentifier(),
		Args: Args{
			ScanRequest: &request,
		},
	}

	scanJob := job.ScanJob{
		ID:     j.ID,
		Status: job.Queued,
	}

	// Save the job status to Redis
	if err := e.store.Create(ctx, scanJob); err != nil {
		return job.ScanJob{}, xerrors.Errorf("creating scan job %v", err)
	}

	b, err := json.Marshal(j)
	if err != nil {
		return job.ScanJob{}, xerrors.Errorf("marshalling scan request: %v", err)
	}

	// Publish the job to the workers
	if err = e.rdb.Publish(ctx, e.redisJobChannel(), b).Err(); err != nil {
		return job.ScanJob{}, xerrors.Errorf("enqueuing scan artifact job: %v", err)
	}

	slog.Debug("Successfully enqueued scan job", slog.String("job_id", j.ID))

	return scanJob, nil
}

func (e *enqueuer) redisJobChannel() string {
	return redisJobChannel(e.namespace)
}

func makeIdentifier() string {
	b := make([]byte, 12)
	_, err := io.ReadFull(rand.Reader, b)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%x", b)
}

func redisJobChannel(namespace string) string {
	return namespace + "jobs:" + scanArtifactJobName
}
