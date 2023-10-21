package redis

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/harbor"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/job"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/persistence"
	"github.com/gomodule/redigo/redis"
	"golang.org/x/xerrors"
)

type store struct {
	cfg  etc.RedisStore
	pool *redis.Pool
}

func NewStore(cfg etc.RedisStore, pool *redis.Pool) persistence.Store {
	return &store{
		cfg:  cfg,
		pool: pool,
	}
}

func (s *store) Create(scanJob job.ScanJob) error {
	conn := s.pool.Get()
	defer s.close(conn)

	bytes, err := json.Marshal(scanJob)
	if err != nil {
		return xerrors.Errorf("marshalling scan job: %w", err)
	}

	key := s.getKeyForScanJob(scanJob.ID)

	slog.Debug("Saving scan job",
		slog.String("scan_job_id", scanJob.ID),
		slog.String("scan_job_status", scanJob.Status.String()),
		slog.String("redis_key", key),
		slog.Duration("expire", s.cfg.ScanJobTTL),
	)

	if _, err = conn.Do("SET", key, string(bytes), "NX", "EX", int(s.cfg.ScanJobTTL.Seconds())); err != nil {
		return xerrors.Errorf("creating scan job: %w", err)
	}

	return nil
}

func (s *store) update(scanJob job.ScanJob) error {
	conn := s.pool.Get()
	defer s.close(conn)

	bytes, err := json.Marshal(scanJob)
	if err != nil {
		return xerrors.Errorf("marshalling scan job: %w", err)
	}

	key := s.getKeyForScanJob(scanJob.ID)

	slog.Debug("Updating scan job",
		slog.String("scan_job_id", scanJob.ID),
		slog.String("scan_job_status", scanJob.Status.String()),
		slog.String("redis_key", key),
		slog.Duration("expire", s.cfg.ScanJobTTL),
	)

	if _, err = conn.Do("SET", key, string(bytes), "XX", "EX", int(s.cfg.ScanJobTTL.Seconds())); err != nil {
		return xerrors.Errorf("updating scan job: %w", err)
	}

	return nil
}

func (s *store) Get(scanJobID string) (*job.ScanJob, error) {
	conn := s.pool.Get()
	defer s.close(conn)

	key := s.getKeyForScanJob(scanJobID)
	value, err := redis.String(conn.Do("GET", key))
	if err != nil {
		if errors.Is(err, redis.ErrNil) {
			return nil, nil
		}
		return nil, err
	}

	var scanJob job.ScanJob
	err = json.Unmarshal([]byte(value), &scanJob)
	if err != nil {
		return nil, err
	}

	return &scanJob, nil
}

func (s *store) UpdateStatus(scanJobID string, newStatus job.ScanJobStatus, error ...string) error {
	slog.Debug("Updating status for scan job", slog.String("scan_job_id", scanJobID),
		slog.String("new_status", newStatus.String()),
	)

	scanJob, err := s.Get(scanJobID)
	if err != nil {
		return err
	}

	scanJob.Status = newStatus
	if len(error) > 0 {
		scanJob.Error = error[0]
	}

	return s.update(*scanJob)
}

func (s *store) UpdateReport(scanJobID string, report harbor.ScanReport) error {
	slog.Debug("Updating reports for scan job", slog.String("scan_job_id", scanJobID))

	scanJob, err := s.Get(scanJobID)
	if err != nil {
		return err
	}

	scanJob.Report = report
	return s.update(*scanJob)
}

func (s *store) getKeyForScanJob(scanJobID string) string {
	return fmt.Sprintf("%s:scan-job:%s", s.cfg.Namespace, scanJobID)
}

func (s *store) close(conn redis.Conn) {
	err := conn.Close()
	if err != nil {
		slog.Error("Error while closing connection", slog.String("err", err.Error()))
	}
}
