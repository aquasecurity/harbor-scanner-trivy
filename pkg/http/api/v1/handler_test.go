package v1

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/harbor"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/http/api"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/job"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/mock"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/trivy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRequestHandler_ValidateScanRequest(t *testing.T) {
	testCases := []struct {
		Name          string
		Request       harbor.ScanRequest
		ExpectedError *harbor.Error
	}{
		{
			Name:    "Should return error when Registry URL is blank",
			Request: harbor.ScanRequest{},
			ExpectedError: &harbor.Error{
				HTTPCode: http.StatusUnprocessableEntity,
				Message:  "missing registry.url",
			},
		},
		{
			Name: "Should return error when Registry URL is invalid",
			Request: harbor.ScanRequest{
				Registry: harbor.Registry{
					URL: "INVALID URL",
				},
			},
			ExpectedError: &harbor.Error{
				HTTPCode: http.StatusUnprocessableEntity,
				Message:  "invalid registry.url",
			},
		},
		{
			Name: "Should return error when artifact repository is blank",
			Request: harbor.ScanRequest{
				Registry: harbor.Registry{
					URL: "https://core.harbor.domain",
				},
			},
			ExpectedError: &harbor.Error{
				HTTPCode: http.StatusUnprocessableEntity,
				Message:  "missing artifact.repository",
			},
		},
		{
			Name: "Should return error when artifact digest is blank",
			Request: harbor.ScanRequest{
				Registry: harbor.Registry{
					URL: "https://core.harbor.domain",
				},
				Artifact: harbor.Artifact{
					Repository: "library/mongo",
				},
			},
			ExpectedError: &harbor.Error{
				HTTPCode: http.StatusUnprocessableEntity,
				Message:  "missing artifact.digest",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			handler := requestHandler{}
			validationError := handler.ValidateScanRequest(tc.Request)
			assert.Equal(t, tc.ExpectedError, validationError)
		})
	}
}

func TestRequestHandler_AcceptScanRequest(t *testing.T) {
	validScanRequest := harbor.ScanRequest{
		Registry: harbor.Registry{
			URL:           "https://core.harbor.domain",
			Authorization: "Bearer JWTTOKENGOESHERE",
		},
		Artifact: harbor.Artifact{
			Repository: "library/oracle/nosql",
			Digest:     "sha256:6c3c624b58dbbcd3c0dd82b4c53f04194d1247c6eebdaab7c610cf7d66709b3b",
		},
	}
	validScanRequestJSON := `{
  "registry": {
    "url": "https://core.harbor.domain",
    "authorization": "Bearer JWTTOKENGOESHERE"
  },
  "artifact": {
    "repository": "library/oracle/nosql",
    "digest": "sha256:6c3c624b58dbbcd3c0dd82b4c53f04194d1247c6eebdaab7c610cf7d66709b3b"
  }
}`

	testCases := []struct {
		name                string
		enqueuerExpectation *mock.Expectation
		requestBody         string
		expectedStatus      int
		expectedContentType string
		expectedResponse    string
	}{
		{
			name: "Should accept scan request",
			enqueuerExpectation: &mock.Expectation{
				Method:     "Enqueue",
				Args:       []interface{}{validScanRequest},
				ReturnArgs: []interface{}{job.ScanJob{ID: "job:123"}, nil},
			},
			requestBody:         validScanRequestJSON,
			expectedStatus:      http.StatusAccepted,
			expectedContentType: "application/vnd.scanner.adapter.scan.response+json; version=1.0",
			expectedResponse:    `{"id": "job:123"}`,
		},
		{
			name:                "Should respond with error 400 when scan request cannot be parsed",
			requestBody:         "THIS AIN'T PARSE",
			expectedStatus:      http.StatusBadRequest,
			expectedContentType: "application/vnd.scanner.adapter.error; version=1.0",
			expectedResponse: `{
  "error": {
    "message": "unmarshalling scan request: invalid character 'T' looking for beginning of value"
  }
}`,
		},
		{
			name:                "Should respond with error 422 when scan request can be parsed but has invalid values",
			requestBody:         `{}`,
			expectedStatus:      http.StatusUnprocessableEntity,
			expectedContentType: api.MimeTypeError.String(),
			expectedResponse: `{
  "error": {
    "message": "missing registry.url"
  }
}`,
		},
		{
			name: "Should respond with error 500 when enqueuing scan request fails",
			enqueuerExpectation: &mock.Expectation{
				Method:     "Enqueue",
				Args:       []interface{}{validScanRequest},
				ReturnArgs: []interface{}{job.ScanJob{}, errors.New("queue is down")},
			},
			requestBody:         validScanRequestJSON,
			expectedStatus:      http.StatusInternalServerError,
			expectedContentType: "application/vnd.scanner.adapter.error; version=1.0",
			expectedResponse: `{
  "error": {
    "message": "enqueuing scan job: queue is down"
  }
}`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			enqueuer := mock.NewEnqueuer()
			store := mock.NewStore()

			mock.ApplyExpectations(t, enqueuer, tc.enqueuerExpectation)

			rr := httptest.NewRecorder()
			r, err := http.NewRequest(http.MethodPost, "/api/v1/scan", strings.NewReader(tc.requestBody))
			require.NoError(t, err)

			NewAPIHandler(etc.BuildInfo{}, etc.Config{}, enqueuer, store, nil).ServeHTTP(rr, r)

			assert.Equal(t, tc.expectedStatus, rr.Code)
			assert.Equal(t, tc.expectedContentType, rr.Header().Get("Content-Type"))

			assert.JSONEq(t, tc.expectedResponse, rr.Body.String())

			enqueuer.AssertExpectations(t)
			store.AssertExpectations(t)
		})
	}
}

func TestRequestHandler_GetScanReport(t *testing.T) {
	now := time.Now()

	testCases := []struct {
		name                string
		storeExpectation    *mock.Expectation
		expectedStatus      int
		expectedContentType string
		expectedResponse    string
	}{
		{
			name: "Should respond with error 500 when retrieving scan job fails",
			storeExpectation: &mock.Expectation{
				Method:     "Get",
				Args:       []interface{}{"job:123"},
				ReturnArgs: []interface{}{&job.ScanJob{}, errors.New("data store is down")},
			},
			expectedStatus:      http.StatusInternalServerError,
			expectedContentType: "application/vnd.scanner.adapter.error; version=1.0",
			expectedResponse: `{
  "error": {
    "message": "getting scan job: data store is down"
  }
}`,
		},
		{
			name: "Should respond with error 404 when scan job cannot be found",
			storeExpectation: &mock.Expectation{
				Method:     "Get",
				Args:       []interface{}{"job:123"},
				ReturnArgs: []interface{}{(*job.ScanJob)(nil), nil},
			},
			expectedStatus:      http.StatusNotFound,
			expectedContentType: "application/vnd.scanner.adapter.error; version=1.0",
			expectedResponse: `{
  "error": {
    "message": "cannot find scan job: job:123"
  }
}`,
		},
		{
			name: fmt.Sprintf("Should respond with found status 302 when scan job is %s", job.Queued),
			storeExpectation: &mock.Expectation{
				Method: "Get",
				Args:   []interface{}{"job:123"},
				ReturnArgs: []interface{}{&job.ScanJob{
					ID:     "job:123",
					Status: job.Queued,
				}, nil},
			},
			expectedStatus: http.StatusFound,
		},
		{
			name: fmt.Sprintf("Should respond with found status 302 when scan job is %s", job.Pending),
			storeExpectation: &mock.Expectation{
				Method: "Get",
				Args:   []interface{}{"job:123"},
				ReturnArgs: []interface{}{&job.ScanJob{
					ID:     "job:123",
					Status: job.Pending,
				}, nil},
			},
			expectedStatus: http.StatusFound,
		},
		{
			name: fmt.Sprintf("Should respond with error 500 when scan job is %s", job.Failed),
			storeExpectation: &mock.Expectation{
				Method: "Get",
				Args:   []interface{}{"job:123"},
				ReturnArgs: []interface{}{&job.ScanJob{
					ID:     "job:123",
					Status: job.Failed,
					Error:  "queue worker failed",
				}, nil},
			},
			expectedStatus:      http.StatusInternalServerError,
			expectedContentType: "application/vnd.scanner.adapter.error; version=1.0",
			expectedResponse: `{
  "error": {
    "message": "queue worker failed"
  }
}`,
		},
		{
			name: fmt.Sprintf("Should respond with error 500 when scan job is NOT %s", job.Finished),
			storeExpectation: &mock.Expectation{
				Method: "Get",
				Args:   []interface{}{"job:123"},
				ReturnArgs: []interface{}{&job.ScanJob{
					ID:     "job:123",
					Status: 666,
					Error:  "queue worker failed",
				}, nil},
			},
			expectedStatus:      http.StatusInternalServerError,
			expectedContentType: "application/vnd.scanner.adapter.error; version=1.0",
			expectedResponse: `{
  "error": {
    "message": "unexpected status Unknown of scan job job:123"
  }
}`,
		},
		{
			name: "Should respond with vulnerabilities report",
			storeExpectation: &mock.Expectation{
				Method: "Get",
				Args:   []interface{}{"job:123"},
				ReturnArgs: []interface{}{&job.ScanJob{
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
							Version: "0.1.6",
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
				}, nil},
			},
			expectedStatus:      http.StatusOK,
			expectedContentType: "application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0",
			expectedResponse: fmt.Sprintf(`{
  "generated_at": "%s",
  "artifact": {
    "repository": "library/mongo",
    "digest": "sha256:6c3c624b58dbbcd3c0dd82b4c53f04194d1247c6eebdaab7c610cf7d66709b3b"
  },
  "scanner": {
    "name": "Trivy",
    "vendor": "Aqua Security",
    "version": "0.1.6"
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
}`, now.Format(time.RFC3339Nano)),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			enqueuer := mock.NewEnqueuer()
			store := mock.NewStore()

			mock.ApplyExpectations(t, store, tc.storeExpectation)

			rr := httptest.NewRecorder()
			r, err := http.NewRequest(http.MethodGet, "/api/v1/scan/job:123/report", nil)
			require.NoError(t, err)

			NewAPIHandler(etc.BuildInfo{}, etc.Config{}, enqueuer, store, nil).ServeHTTP(rr, r)

			assert.Equal(t, tc.expectedStatus, rr.Code)
			assert.Equal(t, tc.expectedContentType, rr.Header().Get("Content-Type"))
			if tc.expectedResponse != "" {
				assert.JSONEq(t, tc.expectedResponse, rr.Body.String())
			}

			enqueuer.AssertExpectations(t)
			store.AssertExpectations(t)
		})
	}
}

func TestRequestHandler_GetHealthy(t *testing.T) {
	enqueuer := mock.NewEnqueuer()
	store := mock.NewStore()

	rr := httptest.NewRecorder()

	r, err := http.NewRequest(http.MethodGet, "/probe/healthy", nil)
	require.NoError(t, err)

	NewAPIHandler(etc.BuildInfo{}, etc.Config{}, enqueuer, store, nil).ServeHTTP(rr, r)

	rs := rr.Result()

	assert.Equal(t, http.StatusOK, rs.StatusCode)
	enqueuer.AssertExpectations(t)
	store.AssertExpectations(t)
}

func TestRequestHandler_GetReady(t *testing.T) {
	enqueuer := mock.NewEnqueuer()
	store := mock.NewStore()

	rr := httptest.NewRecorder()

	r, err := http.NewRequest(http.MethodGet, "/probe/ready", nil)
	require.NoError(t, err)

	NewAPIHandler(etc.BuildInfo{}, etc.Config{}, enqueuer, store, nil).ServeHTTP(rr, r)

	rs := rr.Result()

	assert.Equal(t, http.StatusOK, rs.StatusCode)
	enqueuer.AssertExpectations(t)
	store.AssertExpectations(t)
}

func TestRequestHandler_GetMetadata(t *testing.T) {
	testCases := []struct {
		name             string
		mockedBuildInfo  etc.BuildInfo
		mockedVersion    trivy.VersionInfo
		mockedConfig     etc.Config
		mockedError      error
		expectedHTTPCode int
		expectedResp     string
		expectedError    error
	}{
		{
			name:            "Should respond with a valid Metadata JSON and HTTP 200 OK",
			mockedBuildInfo: etc.BuildInfo{Version: "0.1", Commit: "abc", Date: "2019-01-03T13:40"},
			mockedVersion: trivy.VersionInfo{
				Version: "v0.5.2-17-g3c9af62",
				VulnerabilityDB: &trivy.Metadata{
					NextUpdate: time.Unix(1584507644, 0).UTC(),
					UpdatedAt:  time.Unix(1584517644, 0).UTC(),
				},
			},
			mockedConfig: etc.Config{Trivy: etc.Trivy{
				SkipUpdate:    false,
				IgnoreUnfixed: true,
				DebugMode:     true,
				Insecure:      true,
				VulnType:      "os,library",
				Severity:      "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
			}},
			expectedHTTPCode: http.StatusOK,
			expectedResp: `{
   "scanner":{
      "name":"Trivy",
      "vendor":"Aqua Security",
      "version":"Unknown"
   },
   "capabilities":[
      {
         "consumes_mime_types":[
            "application/vnd.oci.image.manifest.v1+json",
            "application/vnd.docker.distribution.manifest.v2+json"
         ],
         "produces_mime_types":[
            "application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0",
            "application/vnd.security.vulnerability.report; version=1.1"
         ]
      }
   ],
   "properties":{
      "harbor.scanner-adapter/scanner-type": "os-package-vulnerability",
      "harbor.scanner-adapter/vulnerability-database-next-update-at": "2020-03-18T05:00:44Z",
      "harbor.scanner-adapter/vulnerability-database-updated-at": "2020-03-18T07:47:24Z",
      "org.label-schema.build-date": "2019-01-03T13:40",
      "org.label-schema.vcs": "https://github.com/aquasecurity/harbor-scanner-trivy",
      "org.label-schema.vcs-ref": "abc",
      "org.label-schema.version": "0.1",
      "env.SCANNER_TRIVY_SKIP_UPDATE": "false",
      "env.SCANNER_TRIVY_IGNORE_UNFIXED": "true",
      "env.SCANNER_TRIVY_DEBUG_MODE": "true",
      "env.SCANNER_TRIVY_INSECURE": "true",
      "env.SCANNER_TRIVY_VULN_TYPE": "os,library",
      "env.SCANNER_TRIVY_SEVERITY": "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL"
   }
}`,
		},
		{
			name:            "Should respond with a valid Metadata JSON and HTTP 200 OK, when there's no trivy Metadata present",
			mockedBuildInfo: etc.BuildInfo{Version: "0.1", Commit: "abc", Date: "2019-01-03T13:40"},
			mockedVersion: trivy.VersionInfo{
				Version: "v0.5.2-17-g3c9af62",
			},
			mockedConfig: etc.Config{Trivy: etc.Trivy{
				SkipUpdate:    false,
				IgnoreUnfixed: true,
				DebugMode:     true,
				Insecure:      true,
				VulnType:      "os,library",
				Severity:      "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
			}},
			expectedHTTPCode: http.StatusOK,
			expectedResp: `{
   "scanner":{
      "name":"Trivy",
      "vendor":"Aqua Security",
      "version":"Unknown"
   },
   "capabilities":[
      {
         "consumes_mime_types":[
            "application/vnd.oci.image.manifest.v1+json",
            "application/vnd.docker.distribution.manifest.v2+json"
         ],
         "produces_mime_types":[
            "application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0",
            "application/vnd.security.vulnerability.report; version=1.1"
         ]
      }
   ],
   "properties":{
      "harbor.scanner-adapter/scanner-type": "os-package-vulnerability",
      "org.label-schema.build-date": "2019-01-03T13:40",
      "org.label-schema.vcs": "https://github.com/aquasecurity/harbor-scanner-trivy",
      "org.label-schema.vcs-ref": "abc",
      "org.label-schema.version": "0.1",
      "env.SCANNER_TRIVY_SKIP_UPDATE": "false",
      "env.SCANNER_TRIVY_IGNORE_UNFIXED": "true",
      "env.SCANNER_TRIVY_DEBUG_MODE": "true",
      "env.SCANNER_TRIVY_INSECURE": "true",
      "env.SCANNER_TRIVY_VULN_TYPE": "os,library",
      "env.SCANNER_TRIVY_SEVERITY": "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL"
   }
}`,
		},
		{
			name:            "Should respond with a valid Metadata JSON and HTTP 200 OK when GetVersion fails",
			mockedError:     errors.New("get version failed"),
			mockedBuildInfo: etc.BuildInfo{Version: "0.1", Commit: "abc", Date: "2019-01-03T13:40"},
			mockedConfig: etc.Config{
				Trivy: etc.Trivy{
					VulnType: "os,library",
					Severity: "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
				},
			},
			expectedHTTPCode: http.StatusOK,
			expectedResp: `{
   "scanner":{
      "name":"Trivy",
      "vendor":"Aqua Security",
      "version":"Unknown"
   },
   "capabilities":[
      {
         "consumes_mime_types":[
            "application/vnd.oci.image.manifest.v1+json",
            "application/vnd.docker.distribution.manifest.v2+json"
         ],
         "produces_mime_types":[
            "application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0",
            "application/vnd.security.vulnerability.report; version=1.1"
         ]
      }
   ],
   "properties":{
      "harbor.scanner-adapter/scanner-type": "os-package-vulnerability",
      "org.label-schema.build-date": "2019-01-03T13:40",
      "org.label-schema.vcs": "https://github.com/aquasecurity/harbor-scanner-trivy",
      "org.label-schema.vcs-ref": "abc",
      "org.label-schema.version": "0.1",
      "env.SCANNER_TRIVY_SKIP_UPDATE": "false",
      "env.SCANNER_TRIVY_IGNORE_UNFIXED": "false",
      "env.SCANNER_TRIVY_DEBUG_MODE": "false",
      "env.SCANNER_TRIVY_INSECURE": "false",
      "env.SCANNER_TRIVY_VULN_TYPE": "os,library",
      "env.SCANNER_TRIVY_SEVERITY": "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL"
   }
}`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			enqueuer := mock.NewEnqueuer()
			store := mock.NewStore()
			wrapper := trivy.NewMockWrapper()
			wrapper.On("GetVersion").Return(tc.mockedVersion, tc.mockedError)

			rr := httptest.NewRecorder()

			r, err := http.NewRequest(http.MethodGet, "/api/v1/metadata", nil)
			require.NoError(t, err, tc.name)

			NewAPIHandler(tc.mockedBuildInfo, tc.mockedConfig, enqueuer, store, wrapper).ServeHTTP(rr, r)

			rs := rr.Result()

			assert.Equal(t, tc.expectedHTTPCode, rs.StatusCode, tc.name)
			assert.JSONEq(t, tc.expectedResp, rr.Body.String(), tc.name)

			enqueuer.AssertExpectations(t)
			store.AssertExpectations(t)
			wrapper.AssertExpectations(t)
		})
	}

}
