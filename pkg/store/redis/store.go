package redis

import (
	"encoding/json"
	"fmt"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/model/job"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/store"
	"github.com/gomodule/redigo/redis"
	"golang.org/x/xerrors"
	"log"
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
			TestOnBorrow: nil,
			MaxIdle:      cfg.PoolMaxIdle,
			MaxActive:    cfg.PoolMaxActive,
			Wait:         true,
		},
	}
}

func (rs *redisStore) SaveScanJob(scanJob job.ScanJob) error {
	conn := rs.pool.Get()
	defer rs.close(conn)

	b, err := json.Marshal(scanJob)
	if err != nil {
		return xerrors.Errorf("marshalling scan job: %w", err)
	}

	key := rs.getKeyForScanJob(scanJob.ID)
	_, err = conn.Do("SET", key, string(b))
	if err != nil {
		return xerrors.Errorf("saving scan job: %w", err)
	}

	return nil
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
