package etc

import (
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type Envs map[string]string

func TestGetLogLevel(t *testing.T) {
	testCases := []struct {
		Name             string
		Envs             Envs
		ExpectedLogLevel slog.Level
	}{
		{
			Name:             "Should return default log level when env is not set",
			ExpectedLogLevel: slog.LevelInfo,
		},
		{
			Name: "Should return default log level when env has invalid value",
			Envs: Envs{
				"SCANNER_LOG_LEVEL": "unknown_level",
			},
			ExpectedLogLevel: slog.LevelInfo,
		},
		{
			Name: "Should return log level set as env",
			Envs: Envs{
				"SCANNER_LOG_LEVEL": "debug",
			},
			ExpectedLogLevel: slog.LevelDebug,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			setEnvs(t, tc.Envs)
			assert.Equal(t, tc.ExpectedLogLevel, LogLevel())
		})
	}
}

func TestGetConfig(t *testing.T) {
	testCases := []struct {
		name           string
		envs           Envs
		expectedError  error
		expectedConfig Config
	}{
		{
			name: "Should enable Trivy debug mode when log level is set to debug",
			envs: Envs{
				"SCANNER_LOG_LEVEL": "debug",
			},
			expectedConfig: Config{
				API: API{
					Addr:           ":8080",
					ReadTimeout:    parseDuration(t, "15s"),
					WriteTimeout:   parseDuration(t, "15s"),
					IdleTimeout:    parseDuration(t, "60s"),
					MetricsEnabled: true,
				},
				Trivy: Trivy{
					DebugMode:   true,
					CacheDir:    "/home/scanner/.cache/trivy",
					ReportsDir:  "/home/scanner/.cache/reports",
					VulnType:    "os,library",
					Scanners:    "vuln",
					Severity:    "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
					Insecure:    false,
					GitHubToken: "",
					Timeout:     parseDuration(t, "5m0s"),
				},
				RedisPool: RedisPool{
					URL:               "redis://localhost:6379",
					MaxActive:         5,
					MaxIdle:           5,
					IdleTimeout:       parseDuration(t, "5m"),
					ConnectionTimeout: parseDuration(t, "1s"),
					ReadTimeout:       parseDuration(t, "1s"),
					WriteTimeout:      parseDuration(t, "1s"),
				},
				RedisStore: RedisStore{
					Namespace:  "harbor.scanner.trivy:data-store",
					ScanJobTTL: parseDuration(t, "1h"),
				},
				JobQueue: JobQueue{
					Namespace:         "harbor.scanner.trivy:job-queue",
					WorkerConcurrency: 1,
				},
			},
		},
		{
			name: "Should return default config",
			expectedConfig: Config{
				API: API{
					Addr:           ":8080",
					ReadTimeout:    parseDuration(t, "15s"),
					WriteTimeout:   parseDuration(t, "15s"),
					IdleTimeout:    parseDuration(t, "60s"),
					MetricsEnabled: true,
				},
				Trivy: Trivy{
					DebugMode:   false,
					CacheDir:    "/home/scanner/.cache/trivy",
					ReportsDir:  "/home/scanner/.cache/reports",
					VulnType:    "os,library",
					Scanners:    "vuln",
					Severity:    "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
					Insecure:    false,
					GitHubToken: "",
					Timeout:     parseDuration(t, "5m0s"),
				},
				RedisPool: RedisPool{
					URL:               "redis://localhost:6379",
					MaxActive:         5,
					MaxIdle:           5,
					IdleTimeout:       parseDuration(t, "5m"),
					ConnectionTimeout: parseDuration(t, "1s"),
					ReadTimeout:       parseDuration(t, "1s"),
					WriteTimeout:      parseDuration(t, "1s"),
				},
				RedisStore: RedisStore{
					Namespace:  "harbor.scanner.trivy:data-store",
					ScanJobTTL: parseDuration(t, "1h"),
				},
				JobQueue: JobQueue{
					Namespace:         "harbor.scanner.trivy:job-queue",
					WorkerConcurrency: 1,
				},
			},
		},
		{
			name: "Should overwrite default config with environment variables",
			envs: Envs{
				"SCANNER_API_SERVER_ADDR":            ":4200",
				"SCANNER_API_SERVER_TLS_CERTIFICATE": "/certs/tls.crt",
				"SCANNER_API_SERVER_TLS_KEY":         "/certs/tls.key",
				"SCANNER_API_SERVER_CLIENT_CAS":      "/certs/tls1.crt,/certs/tls2.crt",
				"SCANNER_API_SERVER_TLS_MIN_VERSION": "1.0",
				"SCANNER_API_SERVER_TLS_MAX_VERSION": "1.2",
				"SCANNER_API_SERVER_READ_TIMEOUT":    "1h",
				"SCANNER_API_SERVER_WRITE_TIMEOUT":   "2m",
				"SCANNER_API_SERVER_IDLE_TIMEOUT":    "3m10s",

				"SCANNER_TRIVY_CACHE_DIR":       "/home/scanner/trivy-cache",
				"SCANNER_TRIVY_REPORTS_DIR":     "/home/scanner/trivy-reports",
				"SCANNER_TRIVY_DEBUG_MODE":      "true",
				"SCANNER_TRIVY_VULN_TYPE":       "os,library",
				"SCANNER_TRIVY_SECURITY_CHECKS": "vuln",
				"SCANNER_TRIVY_SEVERITY":        "CRITICAL",
				"SCANNER_TRIVY_IGNORE_UNFIXED":  "true",
				"SCANNER_TRIVY_INSECURE":        "true",
				"SCANNER_TRIVY_SKIP_UPDATE":     "true",
				"SCANNER_TRIVY_OFFLINE_SCAN":    "true",
				"SCANNER_TRIVY_GITHUB_TOKEN":    "<GITHUB_TOKEN>",
				"SCANNER_TRIVY_TIMEOUT":         "15m30s",

				"SCANNER_STORE_REDIS_NAMESPACE":    "store.ns",
				"SCANNER_STORE_REDIS_SCAN_JOB_TTL": "2h45m15s",

				"SCANNER_JOB_QUEUE_REDIS_NAMESPACE":    "job-queue.ns",
				"SCANNER_JOB_QUEUE_WORKER_CONCURRENCY": "3",

				"SCANNER_REDIS_URL":                  "redis://harbor-harbor-redis:6379",
				"SCANNER_REDIS_POOL_MAX_ACTIVE":      "3",
				"SCANNER_REDIS_POOL_MAX_IDLE":        "7",
				"SCANNER_REDIS_POOL_IDLE_TIMEOUT":    "3m",
				"SCANNER_API_SERVER_METRICS_ENABLED": "false",
			},
			expectedConfig: Config{
				API: API{
					Addr:           ":4200",
					TLSCertificate: "/certs/tls.crt",
					TLSKey:         "/certs/tls.key",
					ClientCAs: []string{
						"/certs/tls1.crt",
						"/certs/tls2.crt",
					},
					ReadTimeout:    parseDuration(t, "1h"),
					WriteTimeout:   parseDuration(t, "2m"),
					IdleTimeout:    parseDuration(t, "3m10s"),
					MetricsEnabled: false,
				},
				Trivy: Trivy{
					CacheDir:         "/home/scanner/trivy-cache",
					ReportsDir:       "/home/scanner/trivy-reports",
					DebugMode:        true,
					VulnType:         "os,library",
					Scanners:         "vuln",
					Severity:         "CRITICAL",
					IgnoreUnfixed:    true,
					SkipDBUpdate:     true,
					SkipJavaDBUpdate: false,
					OfflineScan:      true,
					Insecure:         true,
					GitHubToken:      "<GITHUB_TOKEN>",
					Timeout:          parseDuration(t, "15m30s"),
				},
				RedisPool: RedisPool{
					URL:               "redis://harbor-harbor-redis:6379",
					MaxActive:         3,
					MaxIdle:           7,
					IdleTimeout:       parseDuration(t, "3m"),
					ConnectionTimeout: parseDuration(t, "1s"),
					ReadTimeout:       parseDuration(t, "1s"),
					WriteTimeout:      parseDuration(t, "1s"),
				},
				RedisStore: RedisStore{
					Namespace:  "store.ns",
					ScanJobTTL: parseDuration(t, "2h45m15s"),
				},
				JobQueue: JobQueue{
					Namespace:         "job-queue.ns",
					WorkerConcurrency: 3,
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			setEnvs(t, tc.envs)
			config, err := GetConfig()
			assert.Equal(t, tc.expectedError, err)
			assert.Equal(t, tc.expectedConfig, config)
		})
	}
}

func setEnvs(t *testing.T, envs Envs) {
	for k, v := range envs {
		t.Setenv(k, v)
	}
}

func parseDuration(t *testing.T, s string) time.Duration {
	t.Helper()
	duration, err := time.ParseDuration(s)
	require.NoError(t, err)
	return duration
}
