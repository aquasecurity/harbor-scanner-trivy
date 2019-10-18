package harbor

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestScanRequest_GetImageRef(t *testing.T) {
	testCases := []struct {
		name          string
		Request       ScanRequest
		ImageRef      string
		expectedError string
	}{
		{
			name: "mongo",
			Request: ScanRequest{
				Registry: Registry{
					URL: "https://core.harbor.domain",
				},
				Artifact: Artifact{
					Repository: "library/mongo",
					Digest:     "test:ABC",
				},
			},
			ImageRef: "core.harbor.domain/library/mongo@test:ABC",
		},
		{
			name: "nginx",
			Request: ScanRequest{
				Registry: Registry{
					URL: "https://core.harbor.domain:443",
				},
				Artifact: Artifact{Repository: "library/nginx",
					Digest: "test:DEF",
				},
			},
			ImageRef: "core.harbor.domain:443/library/nginx@test:DEF",
		},
		{
			name: "harbor",
			Request: ScanRequest{
				Registry: Registry{
					URL: "http://harbor-harbor-registry:5000",
				},
				Artifact: Artifact{
					Repository: "scanners/mongo",
					Digest:     "test:GHI",
				},
			},
			ImageRef: "harbor-harbor-registry:5000/scanners/mongo@test:GHI",
		},
		{
			name: "invalid registry url",
			Request: ScanRequest{
				Registry: Registry{
					URL: `"http://foo%bar@www.example.com/"`,
				},
			},
			expectedError: `parsing registry URL: parse "http://foo%bar@www.example.com/": first path segment in URL cannot contain colon`,
		},
	}
	for _, tc := range testCases {
		imageRef, err := tc.Request.GetImageRef()
		switch {
		case tc.expectedError != "":
			assert.Equal(t, tc.expectedError, err.Error(), tc.name)
		default:
			assert.NoError(t, err, tc.name)
		}
		assert.Equal(t, tc.ImageRef, imageRef, tc.name)
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
