package model

import (
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/model/harbor"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/model/trivy"
	log "github.com/sirupsen/logrus"
)

type Transformer interface {
	Transform(result trivy.ScanResult) harbor.ScanResult
}

func NewTransformer() Transformer {
	return &transformer{}
}

type transformer struct {
}

func (t *transformer) Transform(source trivy.ScanResult) (target harbor.ScanResult) {
	var vulnerabilities []harbor.VulnerabilityItem

	for _, v := range source.Vulnerabilities {
		vulnerabilities = append(vulnerabilities, harbor.VulnerabilityItem{
			ID:          v.VulnerabilityID,
			Severity:    t.toHarborSeverity(v.Severity),
			Pkg:         v.PkgName,
			Version:     v.InstalledVersion,
			Fixed:       v.FixedVersion,
			Description: v.Description,
			Links:       v.References,
		})
	}

	target = harbor.ScanResult{
		Severity:        t.toComponentsOverview(source),
		Vulnerabilities: vulnerabilities,
	}
	return
}

func (t *transformer) toHarborSeverity(severity string) harbor.Severity {
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

func (t *transformer) toComponentsOverview(sr trivy.ScanResult) (highest harbor.Severity) {
	highest = harbor.SevNone

	for _, vln := range sr.Vulnerabilities {
		sev := t.toHarborSeverity(vln.Severity)
		if sev > highest {
			highest = sev
		}
	}

	return
}
