package persistence

import (
	"context"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/harbor"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/job"
)

type Store interface {
	Create(ctx context.Context, scanJob job.ScanJob) error
	Get(ctx context.Context, scanJobKey job.ScanJobKey) (*job.ScanJob, error)
	UpdateStatus(ctx context.Context, scanJobKey job.ScanJobKey, newStatus job.ScanJobStatus, error ...string) error
	UpdateReport(ctx context.Context, scanJobKey job.ScanJobKey, report harbor.ScanReport) error
}
