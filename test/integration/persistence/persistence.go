package persistence

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/harbor"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/job"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/persistence"
)

// TestStoreInterface is a generic test that is intended to be called by the implementations of the Store interface
func TestStoreInterface(t *testing.T, store persistence.Store, reportTime time.Time) {
	t.Run("CRUD", func(t *testing.T) {
		scanJobID := "123"

		err := store.Create(job.ScanJob{
			ID:     scanJobID,
			Status: job.Queued,
		})
		require.NoError(t, err, "saving scan job should not fail")

		j, err := store.Get(scanJobID)
		require.NoError(t, err, "getting scan job should not fail")
		assert.Equal(t, &job.ScanJob{
			ID:     scanJobID,
			Status: job.Queued,
		}, j)

		err = store.UpdateStatus(scanJobID, job.Pending)
		require.NoError(t, err, "updating scan job status should not fail")

		j, err = store.Get(scanJobID)
		require.NoError(t, err, "getting scan job should not fail")
		assert.Equal(t, &job.ScanJob{
			ID:     scanJobID,
			Status: job.Pending,
		}, j)

		scanReport := harbor.ScanReport{
			GeneratedAt: reportTime,
			Severity:    harbor.SevHigh,
			Vulnerabilities: []harbor.VulnerabilityItem{
				{
					ID: "CVE-2013-1400",
				},
			},
		}

		err = store.UpdateReport(scanJobID, scanReport)
		require.NoError(t, err, "updating scan job reports should not fail")

		j, err = store.Get(scanJobID)
		require.NoError(t, err, "retrieving scan job should not fail")
		require.NotNil(t, j, "retrieved scan job must not be nil")
		assert.Equal(t, &scanReport, j.Report)

		err = store.UpdateStatus(scanJobID, job.Finished)
		require.NoError(t, err)

		time.Sleep(12 * time.Second)

		j, err = store.Get(scanJobID)
		require.NoError(t, err, "retrieve scan job should not fail")
		require.Nil(t, j, "retrieved scan job should be nil, i.e. expired")
	})
}