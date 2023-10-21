package scan

import (
	"log/slog"
	"time"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/harbor"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/trivy"
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
	Transform(artifact harbor.Artifact, source []trivy.Vulnerability) harbor.ScanReport
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

func (t *transformer) Transform(artifact harbor.Artifact, source []trivy.Vulnerability) harbor.ScanReport {
	vulnerabilities := make([]harbor.VulnerabilityItem, len(source))

	for i, v := range source {
		vulnerabilities[i] = harbor.VulnerabilityItem{
			ID:               v.VulnerabilityID,
			Pkg:              v.PkgName,
			Version:          v.InstalledVersion,
			FixVersion:       v.FixedVersion,
			Severity:         t.toHarborSeverity(v.Severity),
			Description:      v.Description,
			Links:            t.toLinks(v.PrimaryURL, v.References),
			Layer:            t.toHarborLayer(v.Layer),
			CweIDs:           v.CweIDs,
			VendorAttributes: t.toVendorAttributes(v.CVSS),
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

func (t *transformer) toLinks(primaryURL string, references []string) []string {
	if primaryURL != "" {
		return []string{primaryURL}
	}
	if references == nil {
		return []string{}
	}
	return references
}

var trivyToHarborSeverityMap = map[string]harbor.Severity{
	"CRITICAL": harbor.SevCritical,
	"HIGH":     harbor.SevHigh,
	"MEDIUM":   harbor.SevMedium,
	"LOW":      harbor.SevLow,
	"UNKNOWN":  harbor.SevUnknown,
}

func (t *transformer) toHarborLayer(tLayer *trivy.Layer) (hLayer *harbor.Layer) {
	if tLayer == nil {
		return
	}
	hLayer = &harbor.Layer{
		Digest: tLayer.Digest,
		DiffID: tLayer.DiffID,
	}
	return
}

func (t *transformer) toHarborSeverity(severity string) harbor.Severity {
	harborSev, ok := trivyToHarborSeverityMap[severity]
	if !ok {
		slog.Warn("Unknown trivy severity", slog.String("severity", severity))
		return harbor.SevUnknown
	}

	return harborSev
}

func (t *transformer) toVendorAttributes(info map[string]trivy.CVSSInfo) map[string]interface{} {
	attributes := make(map[string]interface{})
	if len(info) > 0 {
		attributes["CVSS"] = info
	}
	return attributes
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
