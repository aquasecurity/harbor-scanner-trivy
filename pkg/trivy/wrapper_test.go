package trivy

import (
	"encoding/json"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/fake"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/samber/lo"
	"github.com/stretchr/testify/mock"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/ext"
	"github.com/stretchr/testify/require"
)

var (
	expectedReportJSON = `{
  "SchemaVersion": 2,
  "Results": [
    {
      "Target": "alpine:3.10.2",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2018-6543",
          "PkgName": "binutils",
          "InstalledVersion": "2.30-r1",
          "FixedVersion": "2.30-r2",
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:L/AC:M/Au:N/C:P/I:N/A:N",
              "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N",
              "V2Score": 1.9,
              "V3Score": 4.7
            },
            "redhat": {
              "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
              "V3Score": 5.5
            }
          },
          "Severity": "MEDIUM",
          "References": [
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-6543"
          ],
          "Layer": {
            "Digest": "sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10"
          }
        }
      ]
    }
  ]
}`
	expectedReport = Report{
		Vulnerabilities: []Vulnerability{
			{
				VulnerabilityID:  "CVE-2018-6543",
				PkgName:          "binutils",
				InstalledVersion: "2.30-r1",
				FixedVersion:     "2.30-r2",
				Severity:         "MEDIUM",
				References: []string{
					"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-6543",
				},
				Layer: &Layer{Digest: "sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10"},
				CVSS: map[string]CVSSInfo{
					"nvd": {
						V2Vector: "AV:L/AC:M/Au:N/C:P/I:N/A:N",
						V3Vector: "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N",
						V2Score:  lo.ToPtr[float32](1.9),
						V3Score:  lo.ToPtr[float32](4.7),
					},
					"redhat": {
						V2Vector: "",
						V3Vector: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
						V2Score:  nil,
						V3Score:  lo.ToPtr[float32](5.5),
					},
				},
			},
		},
	}
	expectedVersion = VersionInfo{
		Version: "v0.5.2-17-g3c9af62",
		VulnerabilityDB: &Metadata{
			NextUpdate: time.Unix(1584507644, 0).UTC(),
			UpdatedAt:  time.Unix(1584517644, 0).UTC(),
		},
	}
)

func TestWrapper_Scan(t *testing.T) {
	t.Run("vulnerability", func(t *testing.T) {
		ambassador := ext.NewMockAmbassador()
		ambassador.On("Environ").Return([]string{"HTTP_PROXY=http://someproxy:7777"})
		ambassador.On("LookPath", "trivy").Return("/usr/local/bin/trivy", nil)

		fakeImage := &fake.FakeImage{}
		fakeImage.ManifestReturns(&v1.Manifest{}, nil)
		ambassador.On("RemoteImage", mock.Anything, mock.Anything).Return(fakeImage, nil)

		reportsDir, cacheDir := tmpDirs(t)
		config := etc.Trivy{
			CacheDir:         cacheDir,
			ReportsDir:       reportsDir,
			DebugMode:        true,
			VulnType:         "os,library",
			Scanners:         "vuln",
			Severity:         "CRITICAL,MEDIUM",
			IgnoreUnfixed:    true,
			IgnorePolicy:     "/home/scanner/opa/policy.rego",
			SkipDBUpdate:     true,
			SkipJavaDBUpdate: true,
			GitHubToken:      "<github_token>",
			Insecure:         true,
			Timeout:          5 * time.Minute,
		}

		reportPath := filepath.Join(reportsDir, "scan_report_vuln.json")
		require.NoError(t, os.WriteFile(reportPath, []byte(expectedReportJSON), 0644))
		ambassador.On("TempFile", reportsDir, mock.Anything).Return(os.Open(reportPath))

		ambassador.On("RunCmd", &exec.Cmd{
			Path: "/usr/local/bin/trivy",
			Env: []string{
				"HTTP_PROXY=http://someproxy:7777",
				"TRIVY_USERNAME=dave.loper",
				"TRIVY_PASSWORD=s3cret",
				"GITHUB_TOKEN=<github_token>",
			},
			Args: []string{
				"/usr/local/bin/trivy",
				"image",
				"--no-progress",
				"--severity",
				"CRITICAL,MEDIUM",
				"--vuln-type",
				"os,library",
				"--format",
				"json",
				"--output",
				reportPath,
				"--cache-dir",
				cacheDir,
				"--timeout",
				"5m0s",
				"--scanners",
				"vuln",
				"--ignore-unfixed",
				"--skip-db-update",
				"--skip-java-db-update",
				"--ignore-policy",
				"/home/scanner/opa/policy.rego",
				"--debug",
				"--insecure",
				"alpine:3.10.2",
			},
		},
		).Return([]byte{}, nil)

		imageRef := ImageRef{
			Name: "alpine:3.10.2",
			Auth: BasicAuth{
				Username: "dave.loper",
				Password: "s3cret",
			},
			NonSSL: true,
		}

		got, err := NewWrapper(config, ambassador).Scan(imageRef, ScanOption{Format: FormatJSON})
		require.NoError(t, err)
		require.Equal(t, expectedReport, got)

		ambassador.AssertExpectations(t)
	})

	t.Run("sbom", func(t *testing.T) {
		ambassador := ext.NewMockAmbassador()
		ambassador.On("Environ").Return([]string{"HTTP_PROXY=http://someproxy:7777"})
		ambassador.On("LookPath", "trivy").Return("/usr/local/bin/trivy", nil)

		fakeImage := &fake.FakeImage{}
		fakeImage.ManifestReturns(&v1.Manifest{
			ArtifactType: "application/vnd.goharbor.harbor.sbom.v1",
		}, nil)
		fakeLayer, err := random.Layer(1024, types.DockerLayer)
		require.NoError(t, err, "failed to create fake layer")
		fakeImage.LayersReturns([]v1.Layer{fakeLayer}, nil)
		ambassador.On("RemoteImage", mock.Anything, mock.Anything).Return(fakeImage, nil)

		reportsDir, cacheDir := tmpDirs(t)
		config := etc.Trivy{
			CacheDir:         cacheDir,
			ReportsDir:       reportsDir,
			Scanners:         "vuln",
			VulnType:         "library",
			Severity:         "CRITICAL",
			SkipDBUpdate:     true,
			SkipJavaDBUpdate: true,
			Timeout:          10 * time.Second,
		}

		reportPath := filepath.Join(reportsDir, "scan_report_vuln.json")
		require.NoError(t, os.WriteFile(reportPath, []byte(expectedReportJSON), 0644))
		ambassador.On("TempFile", reportsDir, mock.Anything).Return(os.Open(reportPath))

		sbomPath := filepath.Join(cacheDir, "sbom.json")
		ambassador.On("TempFile", cacheDir, mock.Anything).Return(os.Create(sbomPath))

		ambassador.On("RunCmd", &exec.Cmd{
			Path: "/usr/local/bin/trivy",
			Env: []string{
				"HTTP_PROXY=http://someproxy:7777",
			},
			Args: []string{
				"/usr/local/bin/trivy",
				"sbom",
				"--no-progress",
				"--severity",
				"CRITICAL",
				"--vuln-type",
				"library",
				"--format",
				"json",
				"--output",
				reportPath,
				"--cache-dir",
				cacheDir,
				"--timeout",
				"10s",
				"--skip-db-update",
				"--skip-java-db-update",
				sbomPath,
			},
		},
		).Return([]byte{}, nil)

		imageRef := ImageRef{
			Name: "alpine@sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10",
			Auth: NoAuth{},
		}

		got, err := NewWrapper(config, ambassador).Scan(imageRef, ScanOption{Format: FormatJSON})
		require.NoError(t, err)
		require.Equal(t, expectedReport, got)

		ambassador.AssertExpectations(t)
	})
}

func TestWrapper_GetVersion(t *testing.T) {
	ambassador := ext.NewMockAmbassador()
	ambassador.On("LookPath", "trivy").Return("/usr/local/bin/trivy", nil)

	config := etc.Trivy{
		CacheDir:  "/home/scanner/.cache/trivy",
		DebugMode: true,
	}

	expectedCmdArgs := []string{
		"/usr/local/bin/trivy",
		"--cache-dir",
		"/home/scanner/.cache/trivy",
		"version",
		"--format",
		"json",
	}

	b, _ := json.Marshal(expectedVersion)
	ambassador.On("RunCmd", &exec.Cmd{
		Path: "/usr/local/bin/trivy",
		Args: expectedCmdArgs,
	},
	).Return(b, nil)

	vi, err := NewWrapper(config, ambassador).GetVersion()
	require.NoError(t, err)
	require.Equal(t, expectedVersion, vi)

	ambassador.AssertExpectations(t)
}

func tmpDirs(t *testing.T) (string, string) {
	tmpDir := t.TempDir()
	cacheDir := filepath.Join(tmpDir, "cache")
	require.NoError(t, os.MkdirAll(cacheDir, 0700))
	reportsDir := filepath.Join(tmpDir, "reports")
	require.NoError(t, os.MkdirAll(reportsDir, 0700))

	return cacheDir, reportsDir
}
