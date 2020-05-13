package rethinkdb

import (
	"time"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/harbor"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/job"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/persistence"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/queue"

	r "gopkg.in/rethinkdb/rethinkdb-go.v6"
)

type rethinkdbJob struct {
	ID         string    `json:"id,omitempty"`
	EnqueuedAt time.Time `json:"enqueued_at"`
	AssignedAt time.Time `json:"assigned_at,omitempty"`
	harbor.ScanRequest
}

type enqueuer struct {
	conn  r.QueryExecutor
	store persistence.Store
	cfg   etc.Rethink
}

func NewEnqueuer(conn r.QueryExecutor, store persistence.Store, cfg etc.Rethink) queue.Enqueuer {
	return &enqueuer{
		conn:  conn,
		store: store,
		cfg:   cfg,
	}
}

func (e *enqueuer) Enqueue(request harbor.ScanRequest) (job.ScanJob, error) {
	rj := rethinkdbJob{
		EnqueuedAt:  time.Now().UTC(),
		ScanRequest: request,
	}

	res, err := r.Table(e.cfg.JobsTable).Insert(rj).RunWrite(e.conn)
	if err != nil || res.Inserted != 1 || len(res.GeneratedKeys) != 1 {
		return job.ScanJob{}, xerrors.Errorf("inserting job to queue failed: %w", err)
	}

	scanJob := job.ScanJob{
		ID:     res.GeneratedKeys[0],
		Status: job.Queued,
	}

	if err = e.store.Create(scanJob); err != nil {
		return job.ScanJob{}, xerrors.Errorf("creating scan job failed: %w", err)
	}

	return scanJob, nil
}
