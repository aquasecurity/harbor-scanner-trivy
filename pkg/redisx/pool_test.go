package redisx

import (
	"testing"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/etc"
	"github.com/stretchr/testify/assert"
)

func TestGetPool(t *testing.T) {

	t.Run("Should return error when configured to connect to secure redis", func(t *testing.T) {
		_, err := NewPool(etc.RedisPool{
			URL: "rediss://hostname:6379",
		})
		assert.EqualError(t, err, "invalid redis URL scheme: rediss")
	})

	t.Run("Should return error when configured with unsupported url scheme", func(t *testing.T) {
		_, err := NewPool(etc.RedisPool{
			URL: "https://hostname:6379",
		})
		assert.EqualError(t, err, "invalid redis URL scheme: https")
	})

}
