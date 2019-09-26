package redis

import (
	"encoding/json"
	"fmt"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/model/job"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/store"
	"github.com/gomodule/redigo/redis"
	log "github.com/sirupsen/logrus"
	"golang.org/x/xerrors"
)

type redisStore struct {
	namespace string
	pool      redis.Pool
}

func NewDataStore(cfg etc.RedisStoreConfig) store.DataStore {
	return &redisStore{
		namespace: cfg.Namespace,
		pool: redis.Pool{
			Dial: func() (redis.Conn, error) {
				return redis.DialURL(cfg.RedisURL)
			},
			MaxIdle:   cfg.PoolMaxIdle,
			MaxActive: cfg.PoolMaxActive,
			Wait:      true,
		},
	}
}

func (rs *redisStore) SaveScanJob(scanJob job.ScanJob) error {
	conn := rs.pool.Get()
	defer rs.close(conn)

	bytes, err := json.Marshal(scanJob)
	if err != nil {
		return xerrors.Errorf("marshalling scan job: %w", err)
	}

	key := rs.getKeyForScanJob(scanJob.ID)
	_, err = conn.Do("SET", key, string(bytes))
	if err != nil {
		return xerrors.Errorf("saving scan job: %w", err)
	}

	return nil
}

func (rs *redisStore) GetScanJob(scanJobID string) (*job.ScanJob, error) {
	conn := rs.pool.Get()
	defer rs.close(conn)

	key := rs.getKeyForScanJob(scanJobID)
	value, err := redis.String(conn.Do("GET", key))
	if err != nil {
		if err == redis.ErrNil {
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

func (rs *redisStore) UpdateStatus(scanJobID string, newStatus job.ScanJobStatus, error ...string) error {
	log.WithFields(log.Fields{
		"scan_job_id": scanJobID,
		"new_status":  newStatus.String(),
	}).Debug("Updating status for scan job")

	scanJob, err := rs.GetScanJob(scanJobID)
	if err != nil {
		return err
	}

	scanJob.Status = newStatus
	if error != nil && len(error) > 0 {
		scanJob.Error = error[0]
	}

	return rs.SaveScanJob(*scanJob)
}

func (rs *redisStore) UpdateReports(scanJobID string, reports job.ScanReports) error {
	log.WithFields(log.Fields{
		"scan_job_id": scanJobID,
	}).Debug("Updating reports for scan job")

	scanJob, err := rs.GetScanJob(scanJobID)
	if err != nil {
		return err
	}

	scanJob.Reports = reports
	return rs.SaveScanJob(*scanJob)
}

func (rs *redisStore) getKeyForScanJob(scanJobID string) string {
	return fmt.Sprintf("%s:scan-job:%s", rs.namespace, scanJobID)
}

func (rs *redisStore) close(conn redis.Conn) {
	err := conn.Close()
	if err != nil {
		log.Printf("closing connection: %v", err)
	}
}
