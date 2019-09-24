package etc

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestGetRedisStoreConfig(t *testing.T) {
	testCases := []struct {
		Name           string
		Envs           map[string]string
		ExpectedError  error
		ExpectedConfig RedisStoreConfig
	}{
		{
			Name: "Should return default config",
			ExpectedConfig: RedisStoreConfig{
				RedisURL:      "redis://localhost:6379",
				Namespace:     "harbor.scanner.trivy:data-store",
				PoolMaxActive: 5,
				PoolMaxIdle:   5,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			config, err := GetRedisStoreConfig()
			assert.Equal(t, tc.ExpectedError, err)
			assert.Equal(t, tc.ExpectedConfig, config)
		})
	}
}

func TestGetJobQueueConfig(t *testing.T) {
	testCases := []struct {
		Name           string
		Envs           map[string]string
		ExpectedError  error
		ExpectedConfig JobQueueConfig
	}{
		{
			Name: "Should return default config",
			ExpectedConfig: JobQueueConfig{
				RedisURL:          "redis://localhost:6379",
				Namespace:         "harbor.scanner.trivy:job-queue",
				WorkerConcurrency: 1,
				PoolMaxActive:     5,
				PoolMaxIdle:       5,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			config, err := GetJobQueueConfig()
			assert.Equal(t, tc.ExpectedError, err)
			assert.Equal(t, tc.ExpectedConfig, config)
		})
	}
}
