package model

import (
	"testing"
	"time"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/model/harbor"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/model/trivy"
	"github.com/stretchr/testify/assert"
)

type fixedClock struct {
	fixedTime time.Time
}

func (c *fixedClock) Now() time.Time {
	return c.fixedTime
}

func TestTransformer_Transform(t *testing.T) {
	fixedTime := time.Now()
	tf := NewTransformer(&fixedClock{
		fixedTime: fixedTime,
	})

	hr := tf.Transform(harbor.Artifact{
		Repository: "library/mongo",
		Digest:     "sha256:6c3c624b58dbbcd3c0dd82b4c53f04194d1247c6eebdaab7c610cf7d66709b3b",
	}, trivy.ScanResult{
		Vulnerabilities: []trivy.Vulnerability{
			{
				VulnerabilityID:  "CVE-0000-0001",
				PkgName:          "PKG-01",
				InstalledVersion: "PKG-01-VER",
				FixedVersion:     "PKG-01-FIX-VER",
				Severity:         "CRITICAL",
				Description:      "CVE-0000-0001.DESC",
				References: []string{
					"http://cve.com?id=CVE-0000-0001",
					"http://vendor.com?id=CVE-0000-0001",
				},
			},
			{
				VulnerabilityID:  "CVE-0000-0002",
				PkgName:          "PKG-02",
				InstalledVersion: "PKG-02-VER",
				FixedVersion:     "",
				Severity:         "HIGH",
				Description:      "CVE-0000-0002.DESC",
				References: []string{
					"http://cve.com?id=CVE-0000-0002",
				},
			},
			{
				VulnerabilityID:  "CVE-0000-0003",
				PkgName:          "PKG-03",
				InstalledVersion: "PKG-03-VER",
				FixedVersion:     "PKG-03-FIX-VER",
				Severity:         "MEDIUM",
				Description:      "CVE-0000-0003.DESC",
				References: []string{
					"http://cve.com?id=CVE-0000-0003",
				},
			},
			{
				VulnerabilityID:  "CVE-0000-0004",
				PkgName:          "PKG-04",
				InstalledVersion: "PKG-04-VER",
				FixedVersion:     "PKG-04-FIX-VER",
				Severity:         "LOW",
				Description:      "CVE-0000-0004.DESC",
				References: []string{
					"http://cve.com?id=CVE-0000-0004",
				},
			},
			{
				VulnerabilityID:  "CVE-0000-0005",
				PkgName:          "PKG-05",
				InstalledVersion: "PKG-05-VER",
				Severity:         "~~~UNKNOWN~~~",
			},
			{
				VulnerabilityID:  "CVE-0000-0006",
				PkgName:          "PKG-06",
				InstalledVersion: "PKG-06-VER",
				Severity:         "UNKNOWN",
			},
		},
	})
	assert.Equal(t, harbor.ScanReport{
		GeneratedAt: fixedTime,
		Artifact: harbor.Artifact{
			Repository: "library/mongo",
			Digest:     "sha256:6c3c624b58dbbcd3c0dd82b4c53f04194d1247c6eebdaab7c610cf7d66709b3b",
		},
		Scanner: harbor.Scanner{
			Name:    "Trivy",
			Vendor:  "Aqua Security",
			Version: "Unknown",
		},
		Severity: harbor.SevCritical,
		Vulnerabilities: []harbor.VulnerabilityItem{
			{
				ID:          "CVE-0000-0001",
				Pkg:         "PKG-01",
				Version:     "PKG-01-VER",
				FixVersion:  "PKG-01-FIX-VER",
				Severity:    harbor.SevCritical,
				Description: "CVE-0000-0001.DESC",
				Links: []string{
					"http://cve.com?id=CVE-0000-0001",
					"http://vendor.com?id=CVE-0000-0001",
				},
			},
			{
				ID:          "CVE-0000-0002",
				Pkg:         "PKG-02",
				Version:     "PKG-02-VER",
				FixVersion:  "",
				Severity:    harbor.SevHigh,
				Description: "CVE-0000-0002.DESC",
				Links: []string{
					"http://cve.com?id=CVE-0000-0002",
				},
			},
			{
				ID:          "CVE-0000-0003",
				Pkg:         "PKG-03",
				Version:     "PKG-03-VER",
				FixVersion:  "PKG-03-FIX-VER",
				Severity:    harbor.SevMedium,
				Description: "CVE-0000-0003.DESC",
				Links: []string{
					"http://cve.com?id=CVE-0000-0003",
				},
			},
			{
				ID:          "CVE-0000-0004",
				Pkg:         "PKG-04",
				Version:     "PKG-04-VER",
				FixVersion:  "PKG-04-FIX-VER",
				Severity:    harbor.SevLow,
				Description: "CVE-0000-0004.DESC",
				Links: []string{
					"http://cve.com?id=CVE-0000-0004",
				},
			},
			{
				ID:       "CVE-0000-0005",
				Pkg:      "PKG-05",
				Version:  "PKG-05-VER",
				Severity: harbor.SevUnknown,
				Links:    []string{},
			},
			{
				ID:       "CVE-0000-0006",
				Pkg:      "PKG-06",
				Version:  "PKG-06-VER",
				Severity: harbor.SevUnknown,
				Links:    []string{},
			},
		},
	}, hr)
}
