package etc

import (
	"os"
	"time"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/harbor"
	"github.com/caarlos0/env/v6"
	"github.com/sirupsen/logrus"
)

type BuildInfo struct {
	Version string
	Commit  string
	Date    string
}

type Config struct {
	API        API
	Trivy      Trivy
	RedisStore RedisStore
	JobQueue   JobQueue
	RedisPool  RedisPool
}

type Trivy struct {
	CacheDir      string        `env:"SCANNER_TRIVY_CACHE_DIR" envDefault:"/home/scanner/.cache/trivy"`
	ReportsDir    string        `env:"SCANNER_TRIVY_REPORTS_DIR" envDefault:"/home/scanner/.cache/reports"`
	DebugMode     bool          `env:"SCANNER_TRIVY_DEBUG_MODE" envDefault:"false"`
	VulnType      string        `env:"SCANNER_TRIVY_VULN_TYPE" envDefault:"os,library"`
	Severity      string        `env:"SCANNER_TRIVY_SEVERITY" envDefault:"UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL"`
	IgnoreUnfixed bool          `env:"SCANNER_TRIVY_IGNORE_UNFIXED" envDefault:"false"`
	IgnorePolicy  string        `env:"SCANNER_TRIVY_IGNORE_POLICY"`
	SkipUpdate    bool          `env:"SCANNER_TRIVY_SKIP_UPDATE" envDefault:"false"`
	GitHubToken   string        `env:"SCANNER_TRIVY_GITHUB_TOKEN"`
	Insecure      bool          `env:"SCANNER_TRIVY_INSECURE" envDefault:"false"`
	Timeout       time.Duration `env:"SCANNER_TRIVY_TIMEOUT" envDefault:"5m0s"`
}

type API struct {
	Addr           string        `env:"SCANNER_API_SERVER_ADDR" envDefault:":8080"`
	TLSCertificate string        `env:"SCANNER_API_SERVER_TLS_CERTIFICATE"`
	TLSKey         string        `env:"SCANNER_API_SERVER_TLS_KEY"`
	ClientCAs      []string      `env:"SCANNER_API_SERVER_CLIENT_CAS"`
	ReadTimeout    time.Duration `env:"SCANNER_API_SERVER_READ_TIMEOUT" envDefault:"15s"`
	WriteTimeout   time.Duration `env:"SCANNER_API_SERVER_WRITE_TIMEOUT" envDefault:"15s"`
	IdleTimeout    time.Duration `env:"SCANNER_API_SERVER_IDLE_TIMEOUT" envDefault:"60s"`
}

func (c *API) IsTLSEnabled() bool {
	return c.TLSCertificate != "" && c.TLSKey != ""
}

type RedisStore struct {
	Namespace  string        `env:"SCANNER_STORE_REDIS_NAMESPACE" envDefault:"harbor.scanner.trivy:data-store"`
	ScanJobTTL time.Duration `env:"SCANNER_STORE_REDIS_SCAN_JOB_TTL" envDefault:"1h"`
}

type JobQueue struct {
	Namespace         string `env:"SCANNER_JOB_QUEUE_REDIS_NAMESPACE" envDefault:"harbor.scanner.trivy:job-queue"`
	WorkerConcurrency int    `env:"SCANNER_JOB_QUEUE_WORKER_CONCURRENCY" envDefault:"1"`
}

type RedisPool struct {
	URL               string        `env:"SCANNER_REDIS_URL" envDefault:"redis://localhost:6379"`
	MaxActive         int           `env:"SCANNER_REDIS_POOL_MAX_ACTIVE" envDefault:"5"`
	MaxIdle           int           `env:"SCANNER_REDIS_POOL_MAX_IDLE" envDefault:"5"`
	IdleTimeout       time.Duration `env:"SCANNER_REDIS_POOL_IDLE_TIMEOUT" envDefault:"5m"`
	ConnectionTimeout time.Duration `env:"SCANNER_REDIS_POOL_CONNECTION_TIMEOUT" envDefault:"1s"`
	ReadTimeout       time.Duration `env:"SCANNER_REDIS_POOL_READ_TIMEOUT" envDefault:"1s"`
	WriteTimeout      time.Duration `env:"SCANNER_REDIS_POOL_WRITE_TIMEOUT" envDefault:"1s"`
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

func GetConfig() (Config, error) {
	var cfg Config
	err := env.Parse(&cfg)
	if err != nil {
		return cfg, err
	}

	if _, ok := os.LookupEnv("SCANNER_TRIVY_DEBUG_MODE"); !ok {
		if GetLogLevel() == logrus.DebugLevel {
			cfg.Trivy.DebugMode = true
		}
	}

	return cfg, nil
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
