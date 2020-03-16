package trivy

import (
	"encoding/json"
	log "github.com/sirupsen/logrus"
	"golang.org/x/xerrors"
	"io"
)

type ScanReport struct {
	Target          string          `json:"Target"`
	Vulnerabilities []Vulnerability `json:"Vulnerabilities"`
}

type Vulnerability struct {
	VulnerabilityID  string   `json:"VulnerabilityID"`
	PkgName          string   `json:"PkgName"`
	InstalledVersion string   `json:"InstalledVersion"`
	FixedVersion     string   `json:"FixedVersion"`
	Title            string   `json:"Title"`
	Description      string   `json:"Description"`
	Severity         string   `json:"Severity"`
	References       []string `json:"References"`
	LayerID          string   `json:"LayerID"`
}

func ScanReportFrom(reportFile io.Reader) (report ScanReport, err error) {
	var scanReports []ScanReport
	err = json.NewDecoder(reportFile).Decode(&scanReports)
	if err != nil {
		return report, xerrors.Errorf("decoding scan report from file %w", err)
	}

	if len(scanReports) == 0 {
		return report, xerrors.New("expected at least one report")
	}

	// Collect all vulnerabilities to single scanReport to allow showing those in Harbor
	report.Target = scanReports[0].Target
	report.Vulnerabilities = make([]Vulnerability, 0, len(scanReports[0].Vulnerabilities))
	for _, scanReport := range scanReports {
		log.WithField("target", scanReport.Target).Trace("Parsing vulnerabilities")
		report.Vulnerabilities = append(report.Vulnerabilities, scanReport.Vulnerabilities...)
	}

	return
}
