package queue

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/http/api"
	"io"
	"log/slog"

	"github.com/redis/go-redis/v9"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/harbor"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/job"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/persistence"
)

const scanArtifactJobName = "scan_artifact"

type Enqueuer interface {
	Enqueue(ctx context.Context, request harbor.ScanRequest) (string, error)
}

type enqueuer struct {
	namespace string
	rdb       *redis.Client
	store     persistence.Store
}

type Job struct {
	Name string
	Key  job.ScanJobKey
	Args Args
}

func (s *Job) ID() string {
	return s.Key.String()
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

func (e *enqueuer) Enqueue(ctx context.Context, request harbor.ScanRequest) (string, error) {
	if len(request.Capabilities) == 0 {
		return "", xerrors.Errorf("no capabilities provided")
	}

	jobID := makeIdentifier()

	for _, c := range request.Capabilities {
		if c.Type == harbor.CapabilityTypeVulnerability {
			c.Parameters = &harbor.CapabilityAttributes{
				SBOMMediaTypes: []api.MediaType{""},
			}
		}

		for _, mediaType := range lo.FromPtr(c.Parameters).SBOMMediaTypes {
			for _, m := range c.ProducesMIMETypes {
				jobKey := job.ScanJobKey{
					ID:        jobID,
					MIMEType:  m,
					MediaType: mediaType,
				}

				j := Job{
					Name: scanArtifactJobName,
					Key:  jobKey,
					Args: Args{
						ScanRequest: &request,
					},
				}
				scanJob := job.ScanJob{
					Key:    jobKey,
					Status: job.Queued,
				}

				if err := e.enqueue(ctx, j, scanJob); err != nil {
					return "", xerrors.Errorf("enqueuing scan job: %v", err)
				}
			}
		}
	}

	return jobID, nil
}

func (e *enqueuer) enqueue(ctx context.Context, j Job, scanJob job.ScanJob) error {
	logger := slog.With(slog.String("job_id", j.Key.ID), slog.String("mime_type", j.Key.MIMEType.String()))
	logger.Debug("Enqueueing scan job")

	// Save the job status to Redis
	if err := e.store.Create(ctx, scanJob); err != nil {
		return xerrors.Errorf("creating scan job %v", err)
	}

	b, err := json.Marshal(j)
	if err != nil {
		return xerrors.Errorf("marshalling scan request: %v", err)
	}

	// Publish the job to the workers
	if err = e.rdb.Publish(ctx, e.redisJobChannel(), b).Err(); err != nil {
		return xerrors.Errorf("enqueuing scan artifact job: %v", err)
	}

	logger.Debug("Successfully enqueued scan job")
	return nil
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
	return namespace + ":jobs:" + scanArtifactJobName
}
