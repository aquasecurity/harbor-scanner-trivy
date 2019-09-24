package trivy

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/image"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/model/harbor"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/model/trivy"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"golang.org/x/xerrors"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
)

type imageScanner struct {
	cfg etc.Config
}

// NewScanner constructs new Scanner with the given Config.
func NewScanner(cfg etc.Config) (image.Scanner, error) {
	return &imageScanner{
		cfg: cfg,
	}, nil
}

func (s *imageScanner) Scan(req harbor.ScanRequest) (*harbor.ScanResponse, error) {
	scanID, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}

	imageRef, err := s.ToImageRef(req)
	if err != nil {
		return nil, fmt.Errorf("getting image ref: %v", err)
	}

	log.Debugf("Started scanning %s ...", imageRef)

	executable, err := exec.LookPath("trivy")
	if err != nil {
		return nil, err
	}

	cmd := exec.Command(executable,
		"--debug",
		"--cache-dir", s.cfg.TrivyCacheDir,
		"--vuln-type", "os",
		"--format", "json",
		"--output", s.GetScanResultFilePath(scanID),
		imageRef,
	)

	cmd.Env = os.Environ()
	if s.cfg.RegistryUsername != "" && s.cfg.RegistryPassword != "" {
		cmd.Env = append(cmd.Env,
			fmt.Sprintf("TRIVY_USERNAME=%s", s.cfg.RegistryUsername),
			fmt.Sprintf("TRIVY_PASSWORD=%s", s.cfg.RegistryPassword))
	}

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err = cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("running trivy: %v", err)
	}

	log.Debugf("trivy exit code: %d", cmd.ProcessState.ExitCode())
	log.Debugf("Finished scanning %s", imageRef)

	return &harbor.ScanResponse{
		ID: scanID.String(),
	}, nil
}

// ToImageRef returns Docker image reference for the given ScanRequest.
// Example: core.harbor.domain/scanners/mysql@sha256:3b00a364fb74246ca119d16111eb62f7302b2ff66d51e373c2bb209f8a1f3b9e
func (s *imageScanner) ToImageRef(req harbor.ScanRequest) (string, error) {
	registryURL, err := url.Parse(req.Registry.URL)
	if err != nil {
		return "", xerrors.Errorf("parsing registry URL: %w", err)
	}
	return fmt.Sprintf("%s/%s@%s", registryURL.Host, req.Artifact.Repository, req.Artifact.Digest), nil
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
	return filepath.Join(s.cfg.ScannerDataDir, scanID.String()+".json")
}

func (s *imageScanner) toHarborScanResult(srs []trivy.ScanResult) (*harbor.ScanResult, error) {
	var vulnerabilities []harbor.VulnerabilityItem

	for _, sr := range srs {
		for _, v := range sr.Vulnerabilities {
			vulnerabilities = append(vulnerabilities, harbor.VulnerabilityItem{
				ID:          v.VulnerabilityID,
				Severity:    s.toHarborSeverity(v.Severity),
				Pkg:         v.PkgName,
				Version:     v.InstalledVersion,
				Fixed:       v.FixedVersion,
				Description: v.Description,
				Links:       v.References,
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
