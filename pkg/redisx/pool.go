package redisx

import (
	"fmt"
	"net/url"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/etc"

	"github.com/gomodule/redigo/redis"
	log "github.com/sirupsen/logrus"
)

// NewPool constructs a redis.Pool with the specified configuration.
//
// The URI scheme currently supports connections to a standalone Redis server,
// i.e. `redis://user:password@host:port/db-number`.
func NewPool(config etc.RedisPool) (pool *redis.Pool, err error) {
	configURL, err := url.Parse(config.URL)
	if err != nil {
		err = fmt.Errorf("invalid redis URL: %s", err)
		return
	}

	switch configURL.Scheme {
	case "redis":
		pool = newInstancePool(config)
	default:
		err = fmt.Errorf("invalid redis URL scheme: %s", configURL.Scheme)
	}
	return
}

// redis://user:password@host:port/db-number
func newInstancePool(config etc.RedisPool) *redis.Pool {
	return &redis.Pool{
		Dial: func() (redis.Conn, error) {
			log.WithField("url", config.URL).Trace("Connecting to Redis")
			return redis.DialURL(config.URL)
		},
		MaxIdle:     config.MaxIdle,
		MaxActive:   config.MaxActive,
		IdleTimeout: config.IdleTimeout,
		Wait:        true,
	}
}
