package store

import (
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/model/job"
)

type DataStore interface {
	SaveScanJob(scanJob job.ScanJob) error
}
