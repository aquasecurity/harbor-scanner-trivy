package harbor

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestScanRequest_GetImageRef(t *testing.T) {
	testCases := []struct {
		Request  ScanRequest
		ImageRef string
	}{
		{
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
	}
	for _, tc := range testCases {
		imageRef, err := tc.Request.GetImageRef()
		require.NoError(t, err)
		assert.Equal(t, tc.ImageRef, imageRef)
	}
}
