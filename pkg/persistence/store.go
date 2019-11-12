package persistence

import (
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/model/harbor"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/model/job"
)

type Store interface {
	Create(scanJob job.ScanJob) error
	Get(scanJobID string) (*job.ScanJob, error)
	UpdateStatus(scanJobID string, newStatus job.ScanJobStatus, error ...string) error
	UpdateReport(scanJobID string, report harbor.ScanReport) error
}
