package scan

import (
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/model/harbor"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/trivy"
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
		c := controller{}
		imageRef, err := c.ToImageRef(tc.Request)
		require.NoError(t, err)
		assert.Equal(t, tc.ImageRef, imageRef)
	}
}

func TestController_ToRegistryAuth(t *testing.T) {
	testCases := []struct {
		Name          string
		Authorization string
		ExpectedError string
		ExpectedAuth  trivy.RegistryAuth
	}{
		{
			Name:          "A",
			Authorization: "",
			ExpectedAuth:  trivy.RegistryAuth{},
		},
		{
			Name:          "B",
			Authorization: "Basic aGFyYm9yOnMzY3JldA==",
			ExpectedAuth: trivy.RegistryAuth{
				Username: "harbor",
				Password: "s3cret",
			},
		},
	}
	for _, tc := range testCases {
		c := controller{}
		auth, err := c.ToRegistryAuth(tc.Authorization)
		if tc.ExpectedError != "" {
			assert.EqualError(t, err, tc.ExpectedError)
		}
		assert.Equal(t, tc.ExpectedAuth, auth)
	}
}
