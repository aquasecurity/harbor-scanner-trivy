package trivy

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/aquasecurity/harbor-trivy-adapter/pkg/etc"
	"github.com/aquasecurity/harbor-trivy-adapter/pkg/image"
	"github.com/aquasecurity/harbor-trivy-adapter/pkg/model/harbor"
	"github.com/aquasecurity/harbor-trivy-adapter/pkg/model/trivy"
	"github.com/google/uuid"
	"log"
	"os"
	"os/exec"
	"path/filepath"
)

type imageScanner struct {
	cfg *etc.Config
}

func NewScanner(cfg *etc.Config) (image.Scanner, error) {
	if cfg == nil {
		return nil, errors.New("cfg must not be nil")
	}
	return &imageScanner{
		cfg: cfg,
	}, nil
}

func (s *imageScanner) Scan(req harbor.ScanRequest) (*harbor.ScanResponse, error) {
	scanID, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}

	log.Printf("RegistryURL: %s", req.RegistryURL)
	log.Printf("Repository: %s", req.Repository)
	log.Printf("Tag: %s", req.Tag)
	log.Printf("Digest: %s", req.Digest)
	log.Printf("Scan request: %s", scanID.String())

	registryURL := req.RegistryURL
	if s.cfg.RegistryURL != "" {
		log.Printf("Overwriting registry URL %s with %s", req.RegistryURL, s.cfg.RegistryURL)
		registryURL = s.cfg.RegistryURL
	}

	imageToScan := fmt.Sprintf("%s/%s:%s", registryURL, req.Repository, req.Tag)

	log.Printf("Started scanning %s ...", imageToScan)

	executable, err := exec.LookPath("trivy")
	if err != nil {
		return nil, err
	}

	cmd := exec.Command(executable,
		"--debug",
		"--format", "json",
		"--output", s.GetScanResultFilePath(scanID),
		imageToScan,
	)

	cmd.Env = append(os.Environ(),
		fmt.Sprintf("TRIVY_USERNAME=%s", s.cfg.RegistryUsername),
		fmt.Sprintf("TRIVY_PASSWORD=%s", s.cfg.RegistryPassword),
	)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err = cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("running trivy: %v", err)
	}

	log.Printf("trivy exit code: %d", cmd.ProcessState.ExitCode())
	log.Printf("Finished scanning %s", imageToScan)

	return &harbor.ScanResponse{
		DetailsKey: scanID.String(),
	}, nil
}

func (s *imageScanner) GetResult(detailsKey string) (*harbor.ScanResult, error) {
	if detailsKey == "" {
		return nil, errors.New("detailsKey must not be nil")
	}

	scanID, err := uuid.Parse(detailsKey)
	if err != nil {
		return nil, err
	}

	file, err := os.Open(s.GetScanResultFilePath(scanID))
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

func (s *imageScanner) GetScanResultFilePath(scanID uuid.UUID) string {
	return filepath.Join("/tmp/", scanID.String()+".json")
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
	case "HIGH", "CRITICAL":
		return harbor.SevHigh
	case "MEDIUM":
		return harbor.SevMedium
	case "LOW":
		return harbor.SevLow
	case "UNKNOWN":
		return harbor.SevUnknown
	default:
		log.Printf("Unknown trivy severity %s", severity)
		return harbor.SevUnknown
	}
}

func (s *imageScanner) toComponentsOverview(srs []trivy.ScanResult) (harbor.Severity, *harbor.ComponentsOverview) {
	overallSev := harbor.SevNone
	total := 0
	sevToCount := map[harbor.Severity]int{
		harbor.SevHigh:    0,
		harbor.SevMedium:  0,
		harbor.SevLow:     0,
		harbor.SevUnknown: 0,
		harbor.SevNone:    0,
	}

	for _, sr := range srs {
		for _, vln := range sr.Vulnerabilities {
			sev := s.toHarborSeverity(vln.Severity)
			sevToCount[sev]++
			total++
			if sev > overallSev {
				overallSev = sev
			}
		}
	}

	var summary []*harbor.ComponentsOverviewEntry
	for k, v := range sevToCount {
		summary = append(summary, &harbor.ComponentsOverviewEntry{
			Sev:   int(k),
			Count: v,
		})
	}

	return overallSev, &harbor.ComponentsOverview{
		Total:   total,
		Summary: summary,
	}
}
