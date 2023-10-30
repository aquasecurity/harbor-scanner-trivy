package redisx

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"strconv"
	"strings"

	"github.com/redis/go-redis/v9"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/etc"
)

// NewClient constructs a redis.Client with the specified configuration.
//
// The URI scheme currently supports connections to a standalone Redis server,
// i.e. `redis://user:password@host:port/db-number`.
func NewClient(config etc.RedisPool) (*redis.Client, error) {
	configURL, err := url.Parse(config.URL)
	if err != nil {
		return nil, xerrors.Errorf("invalid redis URL: %s", err)
	}

	switch configURL.Scheme {
	case "redis":
		return newInstancePool(config)
	case "redis+sentinel":
		return newSentinelPool(configURL, config)
	default:
		return nil, xerrors.Errorf("invalid redis URL scheme: %s", configURL.Scheme)
	}
}

// redis://user:password@host:port/db-number
func newInstancePool(config etc.RedisPool) (*redis.Client, error) {
	// TODO: Ask the Harbor team about why they use "idle_timeout_seconds" instead of "idle_timeout".
	config.URL = strings.ReplaceAll(config.URL, "idle_timeout_seconds", "idle_timeout")

	slog.Debug("Constructing connection pool for Redis", slog.String("url", config.URL))
	options, err := redis.ParseURL(config.URL)
	if err != nil {
		return nil, xerrors.Errorf("invalid redis URL: %s", err)
	}

	options.MaxIdleConns = config.MaxIdle
	options.MaxActiveConns = config.MaxActive
	options.ConnMaxIdleTime = config.IdleTimeout
	options.OnConnect = func(ctx context.Context, cn *redis.Conn) error {
		slog.Debug("Connecting to Redis", slog.String("connection", cn.String()))
		return nil
	}

	return redis.NewClient(options), nil
}

// redis+sentinel://user:password@sentinel_host1:port1,sentinel_host2:port2/monitor-name/db-number
func newSentinelPool(configURL *url.URL, config etc.RedisPool) (*redis.Client, error) {
	slog.Debug("Constructing connection pool for Redis Sentinel")
	sentinelURL, err := ParseSentinelURL(configURL)
	if err != nil {
		return nil, xerrors.Errorf("invalid redis sentinel URL: %s", err)
	}

	return redis.NewFailoverClient(&redis.FailoverOptions{
		MasterName:    sentinelURL.MonitorName,
		SentinelAddrs: sentinelURL.Addrs,
		DB:            sentinelURL.Database,
		Password:      sentinelURL.Password,

		DialTimeout:  config.ConnectionTimeout,
		ReadTimeout:  config.ReadTimeout,
		WriteTimeout: config.WriteTimeout,

		MaxIdleConns:    config.MaxIdle,
		ConnMaxIdleTime: config.IdleTimeout,

		OnConnect: func(ctx context.Context, cn *redis.Conn) error {
			slog.Debug("Connecting to Redis sentinel", slog.String("connection", cn.String()))
			return nil
		},
	}), nil
}

type SentinelURL struct {
	Password    string
	Addrs       []string
	MonitorName string
	Database    int
}

func ParseSentinelURL(configURL *url.URL) (sentinelURL SentinelURL, err error) {
	ps := strings.Split(configURL.Path, "/")
	if len(ps) < 2 {
		err = fmt.Errorf("invalid redis sentinel URL: no master name")
		return
	}

	if user := configURL.User; user != nil {
		if password, set := user.Password(); set {
			sentinelURL.Password = password
		}
	}

	sentinelURL.Addrs = strings.Split(configURL.Host, ",")
	sentinelURL.MonitorName = ps[1]

	if len(ps) > 2 {
		sentinelURL.Database, err = strconv.Atoi(ps[2])
		if err != nil {
			err = fmt.Errorf("invalid redis sentinel URL: invalid database number: %s", ps[2])
			return
		}
	}

	return
}
