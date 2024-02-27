package harbor

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestScanRequest_GetImageRef(t *testing.T) {
	testCases := []struct {
		name             string
		request          ScanRequest
		expectedImageRef string
		expectedInsecure bool
		expectedError    string
	}{
		{
			name: "Should get imageRef when URL scheme is HTTP and port is not specified",
			request: ScanRequest{
				Registry: Registry{
					URL: "http://core.harbor.domain",
				},
				Artifact: Artifact{
					Repository: "library/mongo",
					Digest:     "test:ABC",
				},
			},
			expectedImageRef: "core.harbor.domain:80/library/mongo@test:ABC",
			expectedInsecure: true,
		},
		{
			name: "Should get imageRef when URL scheme is HTTP and port is specified",
			request: ScanRequest{
				Registry: Registry{
					URL: "http://harbor-harbor-registry:5000",
				},
				Artifact: Artifact{
					Repository: "scanners/mongo",
					Digest:     "test:GHI",
				},
			},
			expectedImageRef: "harbor-harbor-registry:5000/scanners/mongo@test:GHI",
			expectedInsecure: true,
		},
		{
			name: "Should get imageRef when URL scheme is HTTPS and port is not specified",
			request: ScanRequest{
				Registry: Registry{
					URL: "https://core.harbor.domain",
				},
				Artifact: Artifact{
					Repository: "library/mongo",
					Digest:     "test:ABC",
				},
			},
			expectedImageRef: "core.harbor.domain:443/library/mongo@test:ABC",
			expectedInsecure: false,
		},
		{
			name: "Should get imageRef when URL scheme is HTTPS and port is specified",
			request: ScanRequest{
				Registry: Registry{
					URL: "https://core.harbor.domain:8443",
				},
				Artifact: Artifact{
					Repository: "library/nginx",
					Digest:     "test:DEF",
				},
			},
			expectedImageRef: "core.harbor.domain:8443/library/nginx@test:DEF",
			expectedInsecure: false,
		},

		{
			name: "Should return error when registry URL is invalid",
			request: ScanRequest{
				Registry: Registry{
					URL: `"http://foo%bar@www.example.com/"`,
				},
			},
			expectedError: `parsing registry URL: parse "\"http://foo%bar@www.example.com/\"": first path segment in URL cannot contain colon`,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			imageRef, insecure, err := tc.request.GetImageRef()
			switch {
			case tc.expectedError != "":
				assert.EqualError(t, err, tc.expectedError)
			default:
				assert.NoError(t, err, tc.name)
				assert.Equal(t, tc.expectedImageRef, imageRef, tc.name)
				assert.Equal(t, tc.expectedInsecure, insecure)
			}
		})
	}
}

func TestSeverity_MarshalJSON(t *testing.T) {
	testCases := []struct {
		severityLevel    int
		expectedSeverity Severity
	}{
		{
			severityLevel:    1,
			expectedSeverity: SevUnknown,
		},
		{
			severityLevel:    2,
			expectedSeverity: SevLow,
		},
		{
			severityLevel:    3,
			expectedSeverity: SevMedium,
		},
		{
			severityLevel:    4,
			expectedSeverity: SevHigh,
		},
		{
			severityLevel:    5,
			expectedSeverity: SevCritical,
		},
		{
			severityLevel: 666,
		},
	}

	for _, tc := range testCases {
		s := Severity(tc.severityLevel)
		b, err := s.MarshalJSON()
		assert.NoError(t, err)
		assert.Equal(t, `"`+tc.expectedSeverity.String()+`"`, string(b))
	}
}

func TestSeverity_UnmarshalJSON(t *testing.T) {
	testCases := []struct {
		inputSeverityJSON string
		expectedSeverity  string
		expectedError     string
	}{
		{
			inputSeverityJSON: `"Unknown"`,
			expectedSeverity:  "Unknown",
		},
		{
			inputSeverityJSON: `"Medium"`,
			expectedSeverity:  "Medium",
		},
		{
			inputSeverityJSON: `invalid json input`,
			expectedError:     "invalid character 'i' looking for beginning of value",
		},
	}

	for _, tc := range testCases {
		var s Severity
		err := s.UnmarshalJSON([]byte(tc.inputSeverityJSON))
		switch {
		case tc.expectedError != "":
			assert.Equal(t, tc.expectedError, err.Error())
		default:
			assert.NoError(t, err)
		}
		assert.Equal(t, tc.expectedSeverity, s.String())
	}

}

func TestGetScannerMetadata(t *testing.T) {
	tests := []struct {
		name            string
		envs            map[string]string
		expectedScanner Scanner
	}{
		{
			name: "Should return version set via env",
			envs: map[string]string{"TRIVY_VERSION": "0.1.6"},
			expectedScanner: Scanner{
				Name:    "Trivy",
				Vendor:  "Aqua Security",
				Version: "0.1.6",
			},
		},
		{
			name: "Should return unknown version when it is not set via env",
			expectedScanner: Scanner{
				Name:    "Trivy",
				Vendor:  "Aqua Security",
				Version: "Unknown",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for k, v := range tt.envs {
				t.Setenv(k, v)
			}
			assert.Equal(t, tt.expectedScanner, GetScannerMetadata())
		})
	}
}
