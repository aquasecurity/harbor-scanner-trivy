package trivy

import (
	"time"
)

const SchemaVersion = 2

type ScanReport struct {
	SchemaVersion int
	Results       []ScanResult `json:"Results"`
}

type ScanResult struct {
	Target          string          `json:"Target"`
	Vulnerabilities []Vulnerability `json:"Vulnerabilities"`
}

type Metadata struct {
	NextUpdate time.Time `json:"NextUpdate"`
	UpdatedAt  time.Time `json:"UpdatedAt"`
}

type VersionInfo struct {
	Version         string    `json:"Version,omitempty"`
	VulnerabilityDB *Metadata `json:"VulnerabilityDB"`
	JavaDB          *Metadata `json:"JavaDB"`
}

type Layer struct {
	Digest string `json:"Digest"`
	DiffID string `json:"DiffID"`
}

type CVSSInfo struct {
	V2Vector string   `json:"V2Vector,omitempty"`
	V3Vector string   `json:"V3Vector,omitempty"`
	V2Score  *float32 `json:"V2Score,omitempty"`
	V3Score  *float32 `json:"V3Score,omitempty"`
}

type Report struct {
	SBOM            any
	Vulnerabilities []Vulnerability
}

type Vulnerability struct {
	VulnerabilityID  string              `json:"VulnerabilityID"`
	PkgName          string              `json:"PkgName"`
	InstalledVersion string              `json:"InstalledVersion"`
	FixedVersion     string              `json:"FixedVersion"`
	Title            string              `json:"Title"`
	Description      string              `json:"Description"`
	Severity         string              `json:"Severity"`
	References       []string            `json:"References"`
	PrimaryURL       string              `json:"PrimaryURL"`
	Layer            *Layer              `json:"Layer"`
	CVSS             map[string]CVSSInfo `json:"CVSS"`
	CweIDs           []string            `json:"CweIDs"`
}
