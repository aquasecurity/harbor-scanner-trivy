package image

import "github.com/aquasecurity/harbor-scanner-trivy/pkg/model/harbor"

// Scanner defines methods for scanning container images.
type Scanner interface {
	Scan(req harbor.ScanRequest) (*harbor.ScanResponse, error)
	GetResult(digest string) (*harbor.ScanResult, error)
}
