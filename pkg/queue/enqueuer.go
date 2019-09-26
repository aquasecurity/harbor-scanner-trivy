package queue

import (
	"encoding/json"
	"fmt"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/model/harbor"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/model/job"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/store"
	"github.com/gocraft/work"
	"github.com/gomodule/redigo/redis"
	log "github.com/sirupsen/logrus"
)

const (
	scanArtifactJobName = "scan_artifact"
	scanRequestJobArg   = "scan_request"
)

type Enqueuer interface {
	Enqueue(request harbor.ScanRequest) (job.ScanJob, error)
}

type defaultEnqueuer struct {
	enqueuer  *work.Enqueuer
	dataStore store.DataStore
}

func NewEnqueuer(config etc.JobQueueConfig, dataStore store.DataStore) Enqueuer {
	redisPool := &redis.Pool{
		Dial: func() (redis.Conn, error) {
			return redis.DialURL(config.RedisURL)
		},
		MaxActive: config.PoolMaxActive,
		MaxIdle:   config.PoolMaxIdle,
		Wait:      true,
	}

	return &defaultEnqueuer{
		enqueuer:  work.NewEnqueuer(config.Namespace, redisPool),
		dataStore: dataStore,
	}
}

func (se *defaultEnqueuer) Enqueue(request harbor.ScanRequest) (job.ScanJob, error) {
	log.Debug("Enqueueing scan job")

	b, err := json.Marshal(request)
	if err != nil {
		return job.ScanJob{}, fmt.Errorf("marshalling scan request: %v", err)
	}

	j, err := se.enqueuer.Enqueue(scanArtifactJobName, work.Q{
		scanRequestJobArg: string(b),
	})
	if err != nil {
		return job.ScanJob{}, fmt.Errorf("enqueuing scan artifact job: %v", err)
	}
	log.Debug("Successfully enqueued scan job")

	scanJob := job.ScanJob{
		ID:     j.ID,
		Status: job.Queued,
	}

	err = se.dataStore.SaveScanJob(scanJob)
	if err != nil {
		return job.ScanJob{}, fmt.Errorf("saving scan job %v", err)
	}

	return scanJob, nil
}
