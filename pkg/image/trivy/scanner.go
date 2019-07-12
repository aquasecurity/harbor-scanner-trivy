package trivy

import (
	"encoding/json"
	"fmt"
	"github.com/aquasecurity/harbor-trivy-adapter/pkg/image"
	"github.com/aquasecurity/harbor-trivy-adapter/pkg/model/harbor"
	"github.com/aquasecurity/harbor-trivy-adapter/pkg/model/trivy"
	"log"
	"os"
	"os/exec"
)

type imageScanner struct {
}

func NewScanner() (image.Scanner, error) {
	return &imageScanner{
	}, nil
}

func (s *imageScanner) Scan(req harbor.ScanRequest) (*harbor.ScanResponse, error) {
	cmd := exec.Command("trivy",
		"--skip-update",
		"-f", "json",
		"-o", "/tmp/trivy/trivyscan.out",
		"mongo:3.4.21-xenial",
	)

	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	if err != nil {
		return nil, err
	}

	log.Printf("PID %d", cmd.Process.Pid)
	log.Printf("ExitCode %d", cmd.ProcessState.ExitCode())
	return &harbor.ScanResponse{
		// TODO Need to change that to UUID or something.
		DetailsKey: "ABC",
	}, nil
}

func (s *imageScanner) GetResult(detailsKey string) (*harbor.ScanResult, error) {
	file, err := os.Open("/tmp/trivy/trivyscan.out")
	if err != nil {
		return nil, fmt.Errorf("opening scan result file: %v", err)
	}
	var data []trivy.ScanResult
	err = json.NewDecoder(file).Decode(&data)
	if err != nil {
		return nil, fmt.Errorf("decoding scan result file: %v", err)
	}

	return s.toHarborScanResult(data)
}

func (s *imageScanner) toHarborScanResult(srs []trivy.ScanResult) (*harbor.ScanResult, error) {
	var vulnerabilities []*harbor.VulnerabilityItem

	for _, sr := range srs {
		for _, v := range sr.Vulnerabilities {
			vulnerabilities = append(vulnerabilities, &harbor.VulnerabilityItem{
				ID:          v.VulnerabilityID,
				Severity:    s.toHarborSeverity(v.Severity),
				Pkg:         v.PkgName,
				Version:     v.InstalledVersion,
				Description: v.Description,
			})
		}
	}

	severity, overview := s.toComponentsOverview(srs)

	return &harbor.ScanResult{
		Severity:        severity,
		Overview:        overview,
		Vulnerabilities: vulnerabilities,
	}, nil
}

func (s *imageScanner) toHarborSeverity(severity string) harbor.Severity {
	switch severity {
	case "HIGH":
		return harbor.SevHigh
	case "MEDIUM":
		return harbor.SevMedium
	case "LOW":
		return harbor.SevLow
	default:
		log.Printf("Unknown trivy severity %s", severity)
		return harbor.SevUnknown
	}
}

func (s *imageScanner) toComponentsOverview(sr []trivy.ScanResult) (harbor.Severity, *harbor.ComponentsOverview) {
	return harbor.SevHigh, &harbor.ComponentsOverview{
		Total: 24 + 13 + 7 + 1 + 5,
		Summary: []*harbor.ComponentsOverviewEntry{
			{Sev: 1, Count: 24},
			{Sev: 2, Count: 13},
			{Sev: 3, Count: 7},
			{Sev: 4, Count: 1},
			{Sev: 5, Count: 5},
		},
	}
}
