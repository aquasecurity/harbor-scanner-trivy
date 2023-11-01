package scan

import (
	"github.com/samber/lo"
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
	Transform(req harbor.ScanRequest, source trivy.Report) harbor.ScanReport
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

func (t *transformer) Transform(req harbor.ScanRequest, source trivy.Report) harbor.ScanReport {
	report := harbor.ScanReport{
		GeneratedAt: t.clock.Now(),
		Scanner:     etc.GetScannerMetadata(),
		Artifact:    req.Artifact,
	}

	switch req.Scan.Parameters.SBOMMediaType {
	case harbor.MediaTypeSPDX, harbor.MediaTypeCycloneDX:
		report.MediaType = string(req.Scan.Parameters.SBOMMediaType)
		report.SBOM = source.SBOM
	default:
		report.Vulnerabilities = t.transformVulnerabilities(source.Vulnerabilities)
		report.Severity = t.toHighestSeverity(report.Vulnerabilities)
	}

	return report
}

func (t *transformer) transformVulnerabilities(source []trivy.Vulnerability) []harbor.VulnerabilityItem {
	if len(source) == 0 {
		return nil
	}

	return lo.Map(source, func(v trivy.Vulnerability, _ int) harbor.VulnerabilityItem {
		return harbor.VulnerabilityItem{
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
	})
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

func (t *transformer) toHighestSeverity(vulns []harbor.VulnerabilityItem) harbor.Severity {
	highest := lo.MaxBy(vulns, func(a, b harbor.VulnerabilityItem) bool {
		return a.Severity > b.Severity
	})
	return highest.Severity
}
