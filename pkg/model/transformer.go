package model

import (
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/model/harbor"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/model/trivy"
	log "github.com/sirupsen/logrus"
	"time"
)

// Clock wraps the Now method. Introduced to allow replacing the global state with fixed clocks to facilitate testing.
// Now returns the current time.
type Clock interface {
	Now() time.Time
}

type SystemClock struct {
}

func (c *SystemClock) Now() time.Time {
	return time.Now()
}

// Transformer wraps the Transform method.
// Transform transforms Trivy's scan report into Harbor's packages vulnerabilities report.
type Transformer interface {
	Transform(artifact harbor.Artifact, source trivy.ScanResult) harbor.ScanReport
}

type transformer struct {
	clock Clock
}

// NewTransformer constructs a Transformer with the given Clock.
func NewTransformer(clock Clock) Transformer {
	return &transformer{
		clock: clock,
	}
}

func (t *transformer) Transform(artifact harbor.Artifact, source trivy.ScanResult) (target harbor.ScanReport) {
	var vulnerabilities []harbor.VulnerabilityItem

	for _, v := range source.Vulnerabilities {
		vulnerabilities = append(vulnerabilities, harbor.VulnerabilityItem{
			ID:          v.VulnerabilityID,
			Pkg:         v.PkgName,
			Version:     v.InstalledVersion,
			FixVersion:  v.FixedVersion,
			Severity:    t.toHarborSeverity(v.Severity),
			Description: v.Description,
			Links:       t.toLinks(v.References),
		})
	}

	target = harbor.ScanReport{
		GeneratedAt:     t.clock.Now(),
		Scanner:         etc.GetScannerMetadata(),
		Artifact:        artifact,
		Severity:        t.toHighestSeverity(source),
		Vulnerabilities: vulnerabilities,
	}
	return
}

func (t *transformer) toLinks(references []string) []string {
	if references == nil {
		return []string{}
	}
	return references
}

func (t *transformer) toHarborSeverity(severity string) harbor.Severity {
	switch severity {
	case "CRITICAL":
		return harbor.SevCritical
	case "HIGH":
		return harbor.SevHigh
	case "MEDIUM":
		return harbor.SevMedium
	case "LOW":
		return harbor.SevLow
	case "UNKNOWN":
		return harbor.SevUnknown
	default:
		log.WithField("severity", severity).Warn("Unknown trivy severity")
		return harbor.SevUnknown
	}
}

func (t *transformer) toHighestSeverity(sr trivy.ScanResult) (highest harbor.Severity) {
	highest = harbor.SevUnknown

	for _, vln := range sr.Vulnerabilities {
		sev := t.toHarborSeverity(vln.Severity)
		if sev > highest {
			highest = sev
		}
	}

	return
}
