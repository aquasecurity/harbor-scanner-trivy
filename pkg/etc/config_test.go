package etc

import (
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/model/harbor"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
	"time"
)

type Envs map[string]string

func TestGetLogLevel(t *testing.T) {
	testCases := []struct {
		Name             string
		Envs             Envs
		ExpectedLogLevel logrus.Level
	}{
		{
			Name:             "Should return default log level when env is not set",
			ExpectedLogLevel: logrus.InfoLevel,
		},
		{
			Name: "Should return default log level when env has invalid value",
			Envs: Envs{
				"SCANNER_LOG_LEVEL": "unknown_level",
			},
			ExpectedLogLevel: logrus.InfoLevel,
		},
		{
			Name: "Should return log level set as env",
			Envs: Envs{
				"SCANNER_LOG_LEVEL": "trace",
			},
			ExpectedLogLevel: logrus.TraceLevel,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			setenvs(t, tc.Envs)
			assert.Equal(t, tc.ExpectedLogLevel, GetLogLevel())
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
			name: "Should return default config",
			expectedConfig: Config{
				API: API{
					Addr:         ":8080",
					ReadTimeout:  parseDuration(t, "15s"),
					WriteTimeout: parseDuration(t, "15s"),
					IdleTimeout:  parseDuration(t, "60s"),
				},
				Trivy: Trivy{
					CacheDir:   "/root/.cache/trivy",
					ReportsDir: "/root/.cache/reports",
					VulnType:   "os",
				},
				RedisStore: RedisStore{
					RedisURL:      "redis://localhost:6379",
					Namespace:     "harbor.scanner.trivy:data-store",
					PoolMaxActive: 5,
					PoolMaxIdle:   5,
					ScanJobTTL:    parseDuration(t, "1h"),
				},
				JobQueue: JobQueue{
					RedisURL:          "redis://localhost:6379",
					Namespace:         "harbor.scanner.trivy:job-queue",
					WorkerConcurrency: 1,
					PoolMaxActive:     5,
					PoolMaxIdle:       5,
				},
			},
		},
		{
			name: "Should overwrite default config with environment variables",
			envs: Envs{
				"SCANNER_API_SERVER_ADDR":          ":4200",
				"SCANNER_API_SERVER_READ_TIMEOUT":  "1h",
				"SCANNER_API_SERVER_WRITE_TIMEOUT": "2m",
				"SCANNER_API_SERVER_IDLE_TIMEOUT":  "3m10s",

				"SCANNER_TRIVY_CACHE_DIR":   "/home/scanner/trivy-cache",
				"SCANNER_TRIVY_REPORTS_DIR": "/home/scanner/trivy-reports",
				"SCANNER_TRIVY_DEBUG_MODE":  "true",
				"SCANNER_TRIVY_VULN_TYPE":   "os,library",
				"SCANNER_TRIVY_SEVERITY":       "CRITICAL",

				"SCANNER_STORE_REDIS_URL":             "redis://harbor-harbor-redis:6379",
				"SCANNER_STORE_REDIS_NAMESPACE":       "test.namespace",
				"SCANNER_STORE_REDIS_POOL_MAX_ACTIVE": "3",
				"SCANNER_STORE_REDIS_POOL_MAX_IDLE":   "7",
				"SCANNER_STORE_REDIS_SCAN_JOB_TTL":    "2h45m15s",
			},
			expectedConfig: Config{
				API: API{
					Addr:         ":4200",
					ReadTimeout:  parseDuration(t, "1h"),
					WriteTimeout: parseDuration(t, "2m"),
					IdleTimeout:  parseDuration(t, "3m10s"),
				},
				Trivy: Trivy{
					CacheDir:   "/home/scanner/trivy-cache",
					ReportsDir: "/home/scanner/trivy-reports",
					DebugMode:  true,
					VulnType:   "os,library",
					Severity:      "CRITICAL",
				},
				RedisStore: RedisStore{
					RedisURL:      "redis://harbor-harbor-redis:6379",
					Namespace:     "test.namespace",
					PoolMaxActive: 3,
					PoolMaxIdle:   7,
					ScanJobTTL:    parseDuration(t, "2h45m15s"),
				},
				JobQueue: JobQueue{
					RedisURL:          "redis://localhost:6379",
					Namespace:         "harbor.scanner.trivy:job-queue",
					WorkerConcurrency: 1,
					PoolMaxActive:     5,
					PoolMaxIdle:       5,
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			setenvs(t, tc.envs)
			config, err := GetConfig()
			assert.Equal(t, tc.expectedError, err)
			assert.Equal(t, tc.expectedConfig, config)
		})
	}
}

func TestGetScannerMetadata(t *testing.T) {
	testCases := []struct {
		name            string
		envs            Envs
		expectedScanner harbor.Scanner
	}{
		{
			name:            "Should return version set via env",
			envs:            Envs{"TRIVY_VERSION": "0.1.6"},
			expectedScanner: harbor.Scanner{Name: "Trivy", Vendor: "Aqua Security", Version: "0.1.6"},
		},
		{
			name:            "Should return unknown version when it is not set via env",
			expectedScanner: harbor.Scanner{Name: "Trivy", Vendor: "Aqua Security", Version: "Unknown"},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			setenvs(t, tc.envs)
			assert.Equal(t, tc.expectedScanner, GetScannerMetadata())
		})
	}
}

func setenvs(t *testing.T, envs Envs) {
	t.Helper()
	os.Clearenv()
	for k, v := range envs {
		err := os.Setenv(k, v)
		require.NoError(t, err)
	}
}

func parseDuration(t *testing.T, s string) time.Duration {
	t.Helper()
	duration, err := time.ParseDuration(s)
	require.NoError(t, err)
	return duration
}
