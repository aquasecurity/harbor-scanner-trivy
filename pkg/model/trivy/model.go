package trivy

type ScanResult struct {
	Target          string          `json:"Target"`
	Vulnerabilities []Vulnerability `json:"Vulnerabilities"`
}

type Vulnerability struct {
	VulnerabilityID  string   `json:"VulnerabilityID"`
	PkgName          string   `json:"PkgName"`
	InstalledVersion string   `json:"InstalledVersion"`
	Title            string   `json:"Title"`
	Description      string   `json:"Description"`
	// HIGH / MEDIUM / LOW
	Severity         string   `json:"Severity"`
	References       []string `json:"References"`
}
