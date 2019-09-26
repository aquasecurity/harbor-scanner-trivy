package job

import (
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/model/harbor"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/model/trivy"
)

type ScanJobStatus int

const (
	Queued ScanJobStatus = iota
	Pending
	Finished
	Failed
)

func (s ScanJobStatus) String() string {
	if s < 0 || s > 3 {
		return "Unknown"
	}
	return [...]string{"Queued", "Pending", "Finished", "Failed"}[s]
}

type ScanJob struct {
	ID      string        `json:"id"`
	Status  ScanJobStatus `json:"status"`
	Error   string        `json:"error"`
	Reports ScanReports   `json:"reports"`
}

type ScanReports struct {
	TrivyScanReport  trivy.ScanResult  `json:"trivy_scan_report"`
	HarborScanReport harbor.ScanResult `json:"harbor-scan_report"`
}
