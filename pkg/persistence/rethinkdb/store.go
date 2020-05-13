package rethinkdb

import (
	"strings"
	"time"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/harbor"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/job"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/persistence"

	"github.com/sirupsen/logrus"
	"golang.org/x/xerrors"
	r "gopkg.in/rethinkdb/rethinkdb-go.v6"
)

type rethinkdbScanJob struct {
	LastUpdatedAt time.Time `json:"last_updated_at"`
	job.ScanJob
}

type store struct {
	conn r.QueryExecutor
	cfg  etc.Rethink
}

func NewStore(conn r.QueryExecutor, cfg etc.Rethink) persistence.Store {
	return &store{
		conn: conn,
		cfg:  cfg,
	}
}

func (s *store) Create(scanJob job.ScanJob) error {
	logrus.WithFields(logrus.Fields{
		"scan_job_id":     scanJob.ID,
		"scan_job_status": scanJob.Status.String(),
		"rethinkdb_table": s.cfg.ScansTable,
	}).Debug("Saving scan job")

	rsj := rethinkdbScanJob{
		LastUpdatedAt: time.Now().UTC(),
		ScanJob:    scanJob,
	}

	res, err := r.Table(s.cfg.ScansTable).Insert(rsj).RunWrite(s.conn)
	if err != nil || res.Inserted != 1 {
		return xerrors.Errorf("inserting scan job failed: %w", err)
	}

	return nil
}

func (s *store) Get(scanJobID string) (*job.ScanJob, error) {
	scanJob := new(job.ScanJob)
	if err := r.Table(s.cfg.ScansTable).Get(scanJobID).ReadOne(scanJob, s.conn); err != nil {
		if err == r.ErrEmptyResult {
			return nil, nil
		}

		return nil, xerrors.Errorf("getting scan job failed: %w", err)
	}

	return scanJob, nil
}

func (s *store) UpdateStatus(scanJobID string, newStatus job.ScanJobStatus, errors ...string) error {
	logrus.WithFields(logrus.Fields{
		"scan_job_id": scanJobID,
		"new_status":  newStatus.String(),
	}).Debug("Updating status for scan job")

	res, err := r.Table(s.cfg.ScansTable).Get(scanJobID).Update(map[interface{}]interface{}{
		"status": newStatus,
		"error":  strings.Join(errors, " --- "),
		"last_updated_at": time.Now().UTC(),
	}).RunWrite(s.conn)
	if err != nil || res.Replaced != 1 {
		return xerrors.Errorf("updating scan job status failed: %w", err)
	}

	return nil
}

func (s *store) UpdateReport(scanJobID string, newReport harbor.ScanReport) error {
	logrus.WithFields(logrus.Fields{
		"scan_job_id": scanJobID,
	}).Debug("Updating report for scan job")

	res, err := r.Table(s.cfg.ScansTable).Get(scanJobID).Update(map[interface{}]interface{}{
		"report": newReport,
		"last_updated_at": time.Now().UTC(),
	}).RunWrite(s.conn)
	if err != nil || res.Replaced != 1 {
		return xerrors.Errorf("updating scan job report failed: %w", err)
	}

	return nil
}
