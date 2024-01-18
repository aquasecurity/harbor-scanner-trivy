//go:build integration

package api

import (
	"fmt"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/http/api"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/harbor"
	v1 "github.com/aquasecurity/harbor-scanner-trivy/pkg/http/api/v1"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/job"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/mock"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/trivy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRestAPI is an integration test for the REST API adapter.
// Tests only happy paths. All branches are covered in the corresponding unit tests.
func TestRestAPI(t *testing.T) {
	if testing.Short() {
		t.Skip("An integration test")
	}

	enqueuer := mock.NewEnqueuer()
	store := mock.NewStore()
	wrapper := trivy.NewMockWrapper()

	app := v1.NewAPIHandler(
		etc.BuildInfo{
			Version: "1.0",
			Commit:  "abc",
			Date:    "2019-01-04T12:40",
		},
		etc.Config{
			Trivy: etc.Trivy{
				SkipDBUpdate:     false,
				SkipJavaDBUpdate: false,
				IgnoreUnfixed:    true,
				DebugMode:        true,
				Insecure:         true,
				VulnType:         "os,library",
				Severity:         "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
				SecurityChecks:   "vuln",
				Timeout:          5 * time.Minute,
			},
		}, enqueuer, store, wrapper)

	ts := httptest.NewServer(app)
	defer ts.Close()

	t.Run("POST /api/v1/scan for vulnerabilities", func(t *testing.T) {
		// given
		enqueuer.On("Enqueue", mock.Anything, harbor.ScanRequest{
			Capabilities: []harbor.Capability{
				{
					Type: harbor.CapabilityTypeVulnerability,
					ProducesMIMETypes: []api.MIMEType{
						api.MimeTypeSecurityVulnerabilityReport,
					},
				},
			},
			Registry: harbor.Registry{
				URL:           "https://core.harbor.domain",
				Authorization: "Bearer JWTTOKENGOESHERE",
			},
			Artifact: harbor.Artifact{
				Repository: "library/oracle/nosql",
				Digest:     "sha256:6c3c624b58dbbcd3c0dd82b4c53f04194d1247c6eebdaab7c610cf7d66709b3b",
			},
		}).Return("job:123", nil)

		// when
		rs, err := ts.Client().Post(ts.URL+"/api/v1/scan", "application/json", strings.NewReader(`{
  "registry": {
    "url": "https://core.harbor.domain",
    "authorization": "Bearer JWTTOKENGOESHERE"
  },
  "artifact": {
    "repository": "library/oracle/nosql",
    "digest": "sha256:6c3c624b58dbbcd3c0dd82b4c53f04194d1247c6eebdaab7c610cf7d66709b3b"
  }
}`))

		// then
		require.NoError(t, err)
		assert.Equal(t, http.StatusAccepted, rs.StatusCode)
		assert.Equal(t, "application/vnd.scanner.adapter.scan.response+json; version=1.0", rs.Header.Get("Content-Type"))

		bodyBytes, err := io.ReadAll(rs.Body)
		require.NoError(t, err)

		assert.JSONEq(t, `{"id": "job:123"}`, string(bodyBytes))
	})

	t.Run("POST /api/v1/scan for SBOM", func(t *testing.T) {
		// given
		enqueuer.On("Enqueue", mock.Anything, harbor.ScanRequest{
			Capabilities: []harbor.Capability{
				{
					Type: harbor.CapabilityTypeSBOM,
					ProducesMIMETypes: []api.MIMEType{
						api.MimeTypeSecuritySBOMReport,
					},
					Parameters: &harbor.CapabilityAttributes{
						SBOMMediaTypes: []api.MediaType{api.MediaTypeSPDX},
					},
				},
			},
			Registry: harbor.Registry{
				URL:           "https://core.harbor.domain",
				Authorization: "Bearer JWTTOKENGOESHERE",
			},
			Artifact: harbor.Artifact{
				Repository: "library/oracle/nosql",
				Digest:     "sha256:6c3c624b58dbbcd3c0dd82b4c53f04194d1247c6eebdaab7c610cf7d66709b3b",
			},
		}).Return("job:123", nil)

		// when
		rs, err := ts.Client().Post(ts.URL+"/api/v1/scan", "application/json", strings.NewReader(`{
  "registry": {
    "url": "https://core.harbor.domain",
    "authorization": "Bearer JWTTOKENGOESHERE"
  },
  "artifact": {
    "repository": "library/oracle/nosql",
    "digest": "sha256:6c3c624b58dbbcd3c0dd82b4c53f04194d1247c6eebdaab7c610cf7d66709b3b"
  },
  "enabled_capabilities": [
    {
      "type": "sbom",
      "produces_mime_types": [
        "application/vnd.security.sbom.report+json; version=1.0"
      ],
      "parameters": {
        "sbom_media_types": [
          "application/spdx+json"
        ]
      }
    }
  ]
}`))

		// then
		require.NoError(t, err)
		assert.Equal(t, http.StatusAccepted, rs.StatusCode)
		assert.Equal(t, "application/vnd.scanner.adapter.scan.response+json; version=1.0", rs.Header.Get("Content-Type"))

		bodyBytes, err := io.ReadAll(rs.Body)
		require.NoError(t, err)

		assert.JSONEq(t, `{"id": "job:123"}`, string(bodyBytes))
	})

	t.Run("GET /api/v1/scan/{scan_request_id}/report for vulnerabilities", func(t *testing.T) {
		// given
		now := time.Now()

		jobKey := job.ScanJobKey{
			ID:       "job:123",
			MIMEType: api.MimeTypeSecurityVulnerabilityReport,
		}
		store.On("Get", mock.Anything, jobKey).Return(&job.ScanJob{
			Key:    jobKey,
			Status: job.Finished,
			Report: harbor.ScanReport{
				GeneratedAt: now,
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
						ID:          "CVE-2019-1111",
						Pkg:         "openssl",
						Version:     "2.0-rc1",
						FixVersion:  "2.1",
						Severity:    harbor.SevCritical,
						Description: "You'd better upgrade your server",
						Links: []string{
							"http://cve.com?id=CVE-2019-1111",
						},
						Layer: &harbor.Layer{
							Digest: "sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10",
						},
					},
				},
			},
		}, nil)

		// when
		rs, err := ts.Client().Get(ts.URL + "/api/v1/scan/job:123/report")
		require.NoError(t, err)

		// then
		assert.Equal(t, http.StatusOK, rs.StatusCode)
		assert.Equal(t, "application/vnd.security.vulnerability.report; version=1.1", rs.Header.Get("Content-Type"))

		bodyBytes, err := io.ReadAll(rs.Body)
		require.NoError(t, err)

		assert.JSONEq(t, fmt.Sprintf(`{
  "generated_at": "%s",
  "artifact": {
    "repository": "library/mongo",
    "digest": "sha256:6c3c624b58dbbcd3c0dd82b4c53f04194d1247c6eebdaab7c610cf7d66709b3b"
  },
  "scanner": {
    "name": "Trivy",
    "vendor": "Aqua Security",
    "version": "Unknown"
  },
  "severity": "Critical",
  "vulnerabilities": [
    {
      "id": "CVE-2019-1111",
      "package": "openssl",
      "version": "2.0-rc1",
      "fix_version": "2.1",
      "severity": "Critical",
      "description": "You'd better upgrade your server",
      "links": [
        "http://cve.com?id=CVE-2019-1111"
      ],
      "layer": {
        "digest": "sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10"
      }
    }
  ]
}`, now.Format(time.RFC3339Nano)), string(bodyBytes))
	})

	t.Run("GET /api/v1/scan/{scan_request_id}/report for SBOM", func(t *testing.T) {
		// given
		now := time.Now()

		jobKey := job.ScanJobKey{
			ID:        "job:123",
			MIMEType:  api.MimeTypeSecuritySBOMReport,
			MediaType: api.MediaTypeSPDX,
		}
		store.On("Get", mock.Anything, jobKey).Return(&job.ScanJob{
			Key:    jobKey,
			Status: job.Finished,
			Report: harbor.ScanReport{
				GeneratedAt: now,
				Artifact: harbor.Artifact{
					Repository: "library/mongo",
					Digest:     "sha256:6c3c624b58dbbcd3c0dd82b4c53f04194d1247c6eebdaab7c610cf7d66709b3b",
				},
				Scanner: harbor.Scanner{
					Name:    "Trivy",
					Vendor:  "Aqua Security",
					Version: "Unknown",
				},
				MediaType: api.MediaTypeSPDX,
				SBOM:      "SPDX Document",
			},
		}, nil)

		// when
		values := url.Values{}
		values.Add("sbom_media_type", "application/spdx+json")
		req, err := http.NewRequest("GET", ts.URL+"/api/v1/scan/job:123/report?"+values.Encode(), nil)
		require.NoError(t, err)
		req.Header.Add("Accept", "application/vnd.security.sbom.report+json; version=1.0")
		rs, err := ts.Client().Do(req)
		require.NoError(t, err)

		// then
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rs.StatusCode)
		assert.Equal(t, "application/vnd.security.sbom.report+json; version=1.0", rs.Header.Get("Content-Type"))

		bodyBytes, err := io.ReadAll(rs.Body)
		require.NoError(t, err)

		expectedSBOMReport := fmt.Sprintf(`{
    "generated_at": "%s",
    "artifact": {
      "repository": "library/mongo",
      "digest": "sha256:6c3c624b58dbbcd3c0dd82b4c53f04194d1247c6eebdaab7c610cf7d66709b3b"
    },
    "scanner": {
      "name": "Trivy",
      "vendor": "Aqua Security",
      "version": "Unknown"
    },
    "media_type": "application/spdx+json",
    "sbom": "SPDX Document"
  }`, now.Format(time.RFC3339Nano))

		assert.JSONEq(t, expectedSBOMReport, string(bodyBytes))
	})

	t.Run("GET /api/v1/metadata", func(t *testing.T) {
		wrapper.On("GetVersion").Return(trivy.VersionInfo{
			Version: "v0.5.2-17-g3c9af62",
			VulnerabilityDB: &trivy.Metadata{
				NextUpdate: time.Unix(1584507644, 0).UTC(),
				UpdatedAt:  time.Unix(1584517644, 0).UTC(),
			},
		}, nil)

		rs, err := ts.Client().Get(ts.URL + "/api/v1/metadata")
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rs.StatusCode)

		bodyBytes, err := io.ReadAll(rs.Body)
		require.NoError(t, err)

		assert.JSONEq(t, `{
  "scanner": {
    "name": "Trivy",
    "vendor": "Aqua Security",
    "version": "Unknown"
  },
  "capabilities": [
    {
      "type": "vulnerability",
      "consumes_mime_types": [
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json"
      ],
      "produces_mime_types": [
        "application/vnd.security.vulnerability.report; version=1.1"
      ]
    },
    {
      "type": "sbom",
      "consumes_mime_types": [
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json"
      ],
      "produces_mime_types": [
        "application/vnd.security.sbom.report+json; version=1.0"
      ],
      "additional_attributes": {
        "sbom_media_types": [
          "application/spdx+json",
          "application/vnd.cyclonedx+json"
        ]
      }
    }
  ],
	"properties": {
	"harbor.scanner-adapter/scanner-type": "os-package-vulnerability",
	"harbor.scanner-adapter/vulnerability-database-next-update-at": "2020-03-18T05:00:44Z",
	"harbor.scanner-adapter/vulnerability-database-updated-at": "2020-03-18T07:47:24Z",
	"org.label-schema.version": "1.0",
	"org.label-schema.build-date": "2019-01-04T12:40",
	"org.label-schema.vcs-ref": "abc",
	"org.label-schema.vcs": "https://github.com/aquasecurity/harbor-scanner-trivy",
	"env.SCANNER_TRIVY_SKIP_UPDATE": "false",
	"env.SCANNER_TRIVY_SKIP_JAVA_DB_UPDATE": "false",
	"env.SCANNER_TRIVY_OFFLINE_SCAN": "false",
	"env.SCANNER_TRIVY_IGNORE_UNFIXED": "true",
	"env.SCANNER_TRIVY_DEBUG_MODE": "true",
	"env.SCANNER_TRIVY_INSECURE": "true",
	"env.SCANNER_TRIVY_VULN_TYPE": "os,library",
	"env.SCANNER_TRIVY_SEVERITY": "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
	"env.SCANNER_TRIVY_SECURITY_CHECKS": "vuln",
	"env.SCANNER_TRIVY_TIMEOUT": "5m0s"
	}
}`, string(bodyBytes))
	})

	t.Run("GET /probe/healthy", func(t *testing.T) {
		rs, err := ts.Client().Get(ts.URL + "/probe/healthy")
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rs.StatusCode)
	})

	t.Run("GET /probe/ready", func(t *testing.T) {
		rs, err := ts.Client().Get(ts.URL + "/probe/ready")
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rs.StatusCode)
	})

	enqueuer.AssertExpectations(t)
	store.AssertExpectations(t)
}
