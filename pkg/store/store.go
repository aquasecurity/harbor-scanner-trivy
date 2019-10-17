package store

import (
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/model/harbor"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/model/job"
)

type DataStore interface {
	SaveScanJob(scanJob job.ScanJob) error
	GetScanJob(scanJobID string) (*job.ScanJob, error)
	UpdateStatus(scanJobID string, newStatus job.ScanJobStatus, error ...string) error
	UpdateReport(scanJobID string, reports harbor.ScanReport) error
}
