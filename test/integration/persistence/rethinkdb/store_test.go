// +build integration

package rethinkdb

import (
	"context"
	"testing"
	"time"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/persistence/rethinkdb"
	"github.com/aquasecurity/harbor-scanner-trivy/test/integration/persistence"

	"github.com/stretchr/testify/require"
	tc "github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// TestStore is an integration test for the RethinkDb persistence store.
func TestStore(t *testing.T) {
	if testing.Short() {
		t.Skip("An integration test")
	}

	ctx := context.Background()
	rethinkdbC, err := tc.GenericContainer(ctx, tc.GenericContainerRequest{
		ContainerRequest: tc.ContainerRequest{
			Image:        "rethinkdb:2.4.0",
			ExposedPorts: []string{"28015/tcp", "8080/tcp"},
			WaitingFor:   wait.ForHTTP("/").WithPort("8080"),
		},
		Started: true,
	})
	require.NoError(t, err, "should start rethinkdb container")
	defer rethinkdbC.Terminate(ctx)

	address, err := rethinkdbC.Endpoint(ctx, "")
	require.NoError(t, err)

	cfg := etc.Rethink{
		Addresses:  []string{address},
		Database:   "trivy",
		ScansTable: "scans",
		JobsTable:  "jobs",
		ScansTTL:   10 * time.Second,
	}

	db, err := etc.GetRethinkdbConnection(cfg)
	require.NoError(t, err, "could not get rethinkdb connection")

	store := rethinkdb.NewStore(db, cfg)
	persistence.TestStoreInterface(t, store, time.Date(2020, 5, 13, 23, 19, 15, 0, time.FixedZone("+00:00", 0)))
}

