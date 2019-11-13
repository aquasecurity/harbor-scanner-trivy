// +build integration

package api

import (
	"fmt"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/etc"
	v1 "github.com/aquasecurity/harbor-scanner-trivy/pkg/http/api/v1"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/mock"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/model/harbor"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/model/job"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestRestApi is an integration test for the REST API adapter.
// Tests only happy paths. All branches are covered in the corresponding unit tests.
func TestRestApi(t *testing.T) {
	if testing.Short() {
		t.Skip("An integration test")
	}

	enqueuer := mock.NewEnqueuer()
	store := mock.NewStore()

	app := v1.NewAPIHandler(etc.BuildInfo{Version:"1.0", Commit:"abc", Date:"2019-01-04T12:40"},enqueuer, store)

	ts := httptest.NewServer(app)
	defer ts.Close()

	t.Run("POST /api/v1/scan", func(t *testing.T) {
		// given
		enqueuer.On("Enqueue", harbor.ScanRequest{
			Registry: harbor.Registry{
				URL:           "https://core.harbor.domain",
				Authorization: "Bearer JWTTOKENGOESHERE",
			},
			Artifact: harbor.Artifact{
				Repository: "library/oracle/nosql",
				Digest:     "sha256:6c3c624b58dbbcd3c0dd82b4c53f04194d1247c6eebdaab7c610cf7d66709b3b",
			},
		}).Return(job.ScanJob{ID: "job:123"}, nil)

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

		bodyBytes, err := ioutil.ReadAll(rs.Body)
		require.NoError(t, err)

		assert.JSONEq(t, `{"id": "job:123"}`, string(bodyBytes))
	})

	t.Run("GET /api/v1/scan/{scan_request_id}/report", func(t *testing.T) {
		// given
		now := time.Now()

		store.On("Get", "job:123").Return(&job.ScanJob{
			ID:     "job:123",
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
					},
				},
			},
		}, nil)

		// when
		rs, err := ts.Client().Get(ts.URL + "/api/v1/scan/job:123/report")
		require.NoError(t, err)

		// then
		assert.Equal(t, http.StatusOK, rs.StatusCode)
		assert.Equal(t, "application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0", rs.Header.Get("Content-Type"))

		bodyBytes, err := ioutil.ReadAll(rs.Body)
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
      ]
    }
  ]
}`, now.Format(time.RFC3339Nano)), string(bodyBytes))
	})

	t.Run("GET /api/v1/metadata", func(t *testing.T) {
		rs, err := ts.Client().Get(ts.URL + "/api/v1/metadata")
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rs.StatusCode)

		bodyBytes, err := ioutil.ReadAll(rs.Body)
		require.NoError(t, err)

		assert.JSONEq(t, `{
  "scanner": {
    "name": "Trivy",
    "vendor": "Aqua Security",
    "version": "Unknown"
  },
  "capabilities": [
    {
      "consumes_mime_types": [
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json"
      ],
      "produces_mime_types": [
        "application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0"
      ]
    }
  ],
  "properties": {
    "harbor.scanner-adapter/scanner-type": "os-package-vulnerability",
    "org.label-schema.version": "1.0",
    "org.label-schema.build-date": "2019-01-04T12:40",
    "org.label-schema.vcs-ref": "abc",
    "org.label-schema.vcs": "https://github.com/aquasecurity/harbor-scanner-trivy"
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
