// +build integration

package redis

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	tc "github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/persistence/redis"
	"github.com/aquasecurity/harbor-scanner-trivy/test/integration/persistence"
)

// TestStore is an integration test for the Redis persistence store.
func TestStore(t *testing.T) {
	if testing.Short() {
		t.Skip("An integration test")
	}

	ctx := context.Background()
	redisC, err := tc.GenericContainer(ctx, tc.GenericContainerRequest{
		ContainerRequest: tc.ContainerRequest{
			Image:        "redis:5.0.5",
			ExposedPorts: []string{"6379/tcp"},
			WaitingFor:   wait.ForLog("Ready to accept connections"),
		},
		Started: true,
	})
	require.NoError(t, err, "should start redis container")
	defer redisC.Terminate(ctx)

	redisURL, err := redisC.Endpoint(ctx, "redis")
	require.NoError(t, err)

	store := redis.NewStore(etc.RedisStore{
		RedisURL:      redisURL,
		Namespace:     "harbor.scanner.trivy:store",
		PoolMaxActive: 5,
		PoolMaxIdle:   5,
		ScanJobTTL:    10 * time.Second,
	})

	persistence.TestStoreInterface(t, store, time.Date(2020, 5, 13, 23, 19, 15, 0, time.UTC))
}
