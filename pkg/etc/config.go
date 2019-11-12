package etc

import (
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/model/harbor"
	"github.com/caarlos0/env/v6"
	"github.com/sirupsen/logrus"
	"os"
	"time"
)

type Config struct {
	API        API
	Trivy      Trivy
	RedisStore RedisStore
	JobQueue   JobQueue
}

type Trivy struct {
	CacheDir   string `env:"SCANNER_TRIVY_CACHE_DIR" envDefault:"/root/.cache/trivy"`
	ReportsDir string `env:"SCANNER_TRIVY_REPORTS_DIR" envDefault:"/root/.cache/reports"`
}

type API struct {
	Addr           string        `env:"SCANNER_API_SERVER_ADDR" envDefault:":8080"`
	TLSCertificate string        `env:"SCANNER_API_SERVER_TLS_CERTIFICATE"`
	TLSKey         string        `env:"SCANNER_API_SERVER_TLS_KEY"`
	ReadTimeout    time.Duration `env:"SCANNER_API_SERVER_READ_TIMEOUT" envDefault:"15s"`
	WriteTimeout   time.Duration `env:"SCANNER_API_SERVER_WRITE_TIMEOUT" envDefault:"15s"`
	IdleTimeout    time.Duration `env:"SCANNER_API_SERVER_IDLE_TIMEOUT" envDefault:"60s"`
}

func (c *API) IsTLSEnabled() bool {
	return c.TLSCertificate != "" && c.TLSKey != ""
}

type RedisStore struct {
	RedisURL      string        `env:"SCANNER_STORE_REDIS_URL" envDefault:"redis://localhost:6379"`
	Namespace     string        `env:"SCANNER_STORE_REDIS_NAMESPACE" envDefault:"harbor.scanner.trivy:data-store"`
	PoolMaxActive int           `env:"SCANNER_STORE_REDIS_POOL_MAX_ACTIVE" envDefault:"5"`
	PoolMaxIdle   int           `env:"SCANNER_STORE_REDIS_POOL_MAX_IDLE" envDefault:"5"`
	ScanJobTTL    time.Duration `env:"SCANNER_STORE_REDIS_SCAN_JOB_TTL" envDefault:"1h"`
}

type JobQueue struct {
	RedisURL          string `env:"SCANNER_JOB_QUEUE_REDIS_URL" envDefault:"redis://localhost:6379"`
	Namespace         string `env:"SCANNER_JOB_QUEUE_REDIS_NAMESPACE" envDefault:"harbor.scanner.trivy:job-queue"`
	WorkerConcurrency int    `env:"SCANNER_JOB_QUEUE_WORKER_CONCURRENCY" envDefault:"1"`
	PoolMaxActive     int    `env:"SCANNER_JOB_QUEUE_REDIS_POOL_MAX_ACTIVE" envDefault:"5"`
	PoolMaxIdle       int    `end:"SCANNER_JOB_QUEUE_REDIS_POOL_MAX_IDLE" envDefault:"5"`
}

func GetLogLevel() logrus.Level {
	if value, ok := os.LookupEnv("SCANNER_LOG_LEVEL"); ok {
		level, err := logrus.ParseLevel(value)
		if err != nil {
			return logrus.InfoLevel
		}
		return level
	}
	return logrus.InfoLevel
}

func GetConfig() (cfg Config, err error) {
	err = env.Parse(&cfg)
	return
}

func GetScannerMetadata() harbor.Scanner {
	version, ok := os.LookupEnv("TRIVY_VERSION")
	if !ok {
		version = "Unknown"
	}
	return harbor.Scanner{
		Name:    "Trivy",
		Vendor:  "Aqua Security",
		Version: version,
	}
}
