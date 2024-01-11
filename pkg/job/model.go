package job

import (
	"fmt"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/harbor"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/http/api"
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
	return [...]string{
		"Queued",
		"Pending",
		"Finished",
		"Failed",
	}[s]
}

// ScanJobKey uniquely identifies a scan job.
// If MIMEType indicates SBOM, MediaType is not empty.
type ScanJobKey struct {
	ID        string        `json:"id"`
	MIMEType  api.MIMEType  `json:"mime_type"`
	MediaType api.MediaType `json:"media_type"` // it can be empty
}

func (s *ScanJobKey) String() string {
	return fmt.Sprintf("%s:%s", s.ID, s.MIMEType.String()) // TODO: add MediaType
}

type ScanJob struct {
	Key    ScanJobKey        `json:"key"` // Must be unique
	Status ScanJobStatus     `json:"status"`
	Error  string            `json:"error"`
	Report harbor.ScanReport `json:"report"`
}

func (s *ScanJob) ID() string {
	return s.Key.String()
}
