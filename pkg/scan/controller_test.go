package scan

import (
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/model/harbor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestController_ToImageRef(t *testing.T) {
	testCases := []struct {
		Request  harbor.ScanRequest
		ImageRef string
	}{
		{
			Request: harbor.ScanRequest{
				Registry: harbor.Registry{
					URL: "https://core.harbor.domain",
				},
				Artifact: harbor.Artifact{
					Repository: "library/mongo",
					Digest:     "test:ABC",
				},
			},
			ImageRef: "core.harbor.domain/library/mongo@test:ABC",
		},
		{
			Request: harbor.ScanRequest{
				Registry: harbor.Registry{
					URL: "https://core.harbor.domain:443",
				},
				Artifact: harbor.Artifact{Repository: "library/nginx",
					Digest: "test:DEF",
				},
			},
			ImageRef: "core.harbor.domain:443/library/nginx@test:DEF",
		},
		{
			Request: harbor.ScanRequest{
				Registry: harbor.Registry{
					URL: "http://harbor-harbor-registry:5000",
				},
				Artifact: harbor.Artifact{
					Repository: "scanners/mongo",
					Digest:     "test:GHI",
				},
			},
			ImageRef: "harbor-harbor-registry:5000/scanners/mongo@test:GHI",
		},
	}
	for _, tc := range testCases {
		s := controller{}
		imageRef, err := s.ToImageRef(tc.Request)
		require.NoError(t, err)
		assert.Equal(t, tc.ImageRef, imageRef)
	}
}
