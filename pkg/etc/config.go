package etc

import (
	"github.com/caarlos0/env/v6"
	"time"
)

type WrapperConfig struct {
	TrivyCacheDir  string
	ScannerDataDir string

	// TODO Those two are just a workaround for Trivy returning 401 error even for public Harbor repository.
	RegistryUsername string `env:"SCANNER_REGISTRY_USERNAME"`
	RegistryPassword string `env:"SCANNER_REGISTRY_PASSWORD"`
}

type APIConfig struct {
	Addr         string        `env:"SCANNER_API_ADDR" envDefault:":8080"`
	ReadTimeout  time.Duration `env:"SCANNER_API_READ_TIMEOUT" envDefault:"15s"`
	WriteTimeout time.Duration `env:"SCANNER_API_WRITE_TIMEOUT" envDefault:"15s"`
}

type RedisStoreConfig struct {
	RedisURL      string `env:"SCANNER_STORE_REDIS_URL" envDefault:"redis://localhost:6379"`
	Namespace     string `env:"SCANNER_STORE_REDIS_NAMESPACE" envDefault:"harbor.scanner.trivy:data-store"`
	PoolMaxActive int    `env:"SCANNER_STORE_REDIS_POOL_MAX_ACTIVE" envDefault:"5"`
	PoolMaxIdle   int    `env:"SCANNER_STORE_REDIS_POOL_MAX_IDLE" envDefault:"5"`
}

type JobQueueConfig struct {
	RedisURL          string `env:"SCANNER_JOB_QUEUE_REDIS_URL" envDefault:"redis://localhost:6379"`
	Namespace         string `env:"SCANNER_JOB_QUEUE_REDIS_NAMESPACE" envDefault:"harbor.scanner.trivy:job-queue"`
	WorkerConcurrency int    `env:"SCANNER_JOB_QUEUE_WORKER_CONCURRENCY" envDefault:"1"`
	PoolMaxActive     int    `env:"SCANNER_JOB_QUEUE_REDIS_POOL_MAX_ACTIVE" envDefault:"5"`
	PoolMaxIdle       int    `end:"SCANNER_JOB_QUEUE_REDIS_POOL_MAX_IDLE" envDefault:"5"`
}

func GetWrapperConfig() (cfg WrapperConfig, err error) {
	err = env.Parse(&cfg)
	return
}

func GetAPIConfig() (cfg APIConfig, err error) {
	err = env.Parse(&cfg)
	return
}

func GetRedisStoreConfig() (cfg RedisStoreConfig, err error) {
	err = env.Parse(&cfg)
	return
}

func GetJobQueueConfig() (cfg JobQueueConfig, err error) {
	err = env.Parse(&cfg)
	return
}
