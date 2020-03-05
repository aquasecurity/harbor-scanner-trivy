package scan

import (
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/model/harbor"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/trivy"
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
	Transform(artifact harbor.Artifact, source trivy.ScanReport) harbor.ScanReport
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

func (t *transformer) Transform(artifact harbor.Artifact, source trivy.ScanReport) (harbor.ScanReport) {
	vulnerabilities := make([]harbor.VulnerabilityItem, len(source.Vulnerabilities))

	for i, v := range source.Vulnerabilities {
		vulnerabilities[i] = harbor.VulnerabilityItem{
			ID:          v.VulnerabilityID,
			Pkg:         v.PkgName,
			Version:     v.InstalledVersion,
			FixVersion:  v.FixedVersion,
			Severity:    t.toHarborSeverity(v.Severity),
			Description: v.Description,
			Links:       t.toLinks(v.References),
			LayerID:     v.LayerID,
		}
	}

	return harbor.ScanReport{
		GeneratedAt:     t.clock.Now(),
		Scanner:         etc.GetScannerMetadata(),
		Artifact:        artifact,
		Severity:        t.toHighestSeverity(vulnerabilities),
		Vulnerabilities: vulnerabilities,
	}
}

func (t *transformer) toLinks(references []string) []string {
	if references == nil {
		return []string{}
	}

	return references
}

var trivyToHarborSeverityMap = map[string]harbor.Severity {
	"CRITICAL": harbor.SevCritical,
	"HIGH":     harbor.SevHigh,
	"MEDIUM":   harbor.SevMedium,
	"LOW":      harbor.SevLow,
	"UNKNOWN":  harbor.SevUnknown,
}

func (t *transformer) toHarborSeverity(severity string) harbor.Severity {
	if harborSev, ok := trivyToHarborSeverityMap[severity]; ok {
		return harborSev
	}

	log.WithField("severity", severity).Warn("Unknown trivy severity")
	return harbor.SevUnknown
}

func (t *transformer) toHighestSeverity(vlns []harbor.VulnerabilityItem) (highest harbor.Severity) {
	highest = harbor.SevUnknown

	for _, vln := range vlns {
		if vln.Severity > highest {
			highest = vln.Severity

			if highest == harbor.SevCritical {
				break
			}
		}

	}

	return
}
