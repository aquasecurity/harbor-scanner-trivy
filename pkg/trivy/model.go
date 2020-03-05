package trivy

import "github.com/opencontainers/go-digest"

type ScanReport struct {
	Target          string          `json:"Target"`
	Vulnerabilities []Vulnerability `json:"Vulnerabilities"`
}

type Vulnerability struct {
	VulnerabilityID  string        `json:"VulnerabilityID"`
	PkgName          string        `json:"PkgName"`
	InstalledVersion string        `json:"InstalledVersion"`
	FixedVersion     string        `json:"FixedVersion"`
	Title            string        `json:"Title"`
	Description      string        `json:"Description"`
	Severity         string        `json:"Severity"`
	References       []string      `json:"References"`
	LayerID          digest.Digest `json:"LayerID"`
}
