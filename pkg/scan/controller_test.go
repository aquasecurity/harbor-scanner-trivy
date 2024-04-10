package scan

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/harbor"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/http/api"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/job"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/mock"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/trivy"
)

var capabilities = []harbor.Capability{
	{
		Type: harbor.CapabilityTypeVulnerability,
		ProducesMIMETypes: []api.MIMEType{
			api.MimeTypeSecurityVulnerabilityReport,
		},
	},
}

func TestController_Scan(t *testing.T) {
	ctx := context.Background()
	artifact := harbor.Artifact{
		Repository: "library/mongo",
		Digest:     "sha256:917f5b7f4bef1b35ee90f03033f33a81002511c1e0767fd44276d4bd9cd2fa8e",
	}
	jobKey := job.ScanJobKey{
		ID:       "job:123",
		MIMEType: api.MimeTypeSecurityVulnerabilityReport,
	}
	trivyReport := trivy.Report{}
	harborReport := harbor.ScanReport{}

	testCases := []struct {
		name string

		scanJobKey             job.ScanJobKey
		scanRequest            harbor.ScanRequest
		storeExpectation       []*mock.Expectation
		wrapperExpectation     *mock.Expectation
		transformerExpectation *mock.Expectation

		expectedError error
	}{
		{
			name:       fmt.Sprintf("Should update job status to %s when everything is fine", job.Finished.String()),
			scanJobKey: jobKey,
			scanRequest: harbor.ScanRequest{
				Registry: harbor.Registry{
					URL:           "https://core.harbor.domain",
					Authorization: "Basic dXNlcjpwYXNzd29yZA==", // user:password
				},
				Artifact:     artifact,
				Capabilities: capabilities,
			},
			storeExpectation: []*mock.Expectation{
				{
					Method: "UpdateStatus",
					Args: []interface{}{
						ctx,
						jobKey,
						job.Pending,
						[]string(nil),
					},
					ReturnArgs: []interface{}{nil},
				},
				{
					Method: "UpdateReport",
					Args: []interface{}{
						ctx,
						jobKey,
						harborReport,
					},
					ReturnArgs: []interface{}{nil},
				},
				{
					Method: "UpdateStatus",
					Args: []interface{}{
						ctx,
						jobKey,
						job.Finished,
						[]string(nil),
					},
					ReturnArgs: []interface{}{nil},
				},
			},
			wrapperExpectation: &mock.Expectation{
				Method: "Scan",
				Args: []interface{}{
					trivy.ImageRef{
						Name: "core.harbor.domain:443/library/mongo@sha256:917f5b7f4bef1b35ee90f03033f33a81002511c1e0767fd44276d4bd9cd2fa8e",
						Auth: trivy.BasicAuth{
							Username: "user",
							Password: "password",
						},
						NonSSL: false,
					},
					trivy.ScanOption{Format: "json"},
				},
				ReturnArgs: []interface{}{
					trivyReport,
					nil,
				},
			},
			transformerExpectation: &mock.Expectation{
				Method: "Transform",
				Args: []interface{}{
					api.MediaType(""),
					harbor.ScanRequest{
						Registry: harbor.Registry{
							URL:           "https://core.harbor.domain",
							Authorization: "Basic dXNlcjpwYXNzd29yZA==", // user:password
						},
						Artifact:     artifact,
						Capabilities: capabilities,
					},
					trivyReport,
				},
				ReturnArgs: []interface{}{
					harborReport,
				},
			},
		},
		{
			name:       fmt.Sprintf("Should update job status to %s when Trivy wrapper fails", job.Failed.String()),
			scanJobKey: jobKey,
			scanRequest: harbor.ScanRequest{
				Registry: harbor.Registry{
					URL:           "https://core.harbor.domain",
					Authorization: "Basic dXNlcjpwYXNzd29yZA==", // user:password
				},
				Artifact: artifact,
				Capabilities: []harbor.Capability{
					{
						Type: harbor.CapabilityTypeVulnerability,
					},
				},
			},
			storeExpectation: []*mock.Expectation{
				{
					Method: "UpdateStatus",
					Args: []interface{}{
						ctx,
						jobKey,
						job.Pending,
						[]string(nil),
					},
					ReturnArgs: []interface{}{nil},
				},
				{
					Method: "UpdateStatus",
					Args: []interface{}{
						ctx,
						jobKey,
						job.Failed,
						[]string{"running trivy wrapper: out of memory"},
					},
					ReturnArgs: []interface{}{nil},
				},
			},
			wrapperExpectation: &mock.Expectation{
				Method: "Scan",
				Args: []interface{}{
					trivy.ImageRef{
						Name: "core.harbor.domain:443/library/mongo@sha256:917f5b7f4bef1b35ee90f03033f33a81002511c1e0767fd44276d4bd9cd2fa8e",
						Auth: trivy.BasicAuth{
							Username: "user",
							Password: "password",
						},
						NonSSL: false,
					},
					trivy.ScanOption{Format: "json"},
				},
				ReturnArgs: []interface{}{
					trivy.Report{},
					xerrors.New("out of memory"),
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			store := mock.NewStore()
			wrapper := trivy.NewMockWrapper()
			transformer := mock.NewTransformer()

			mock.ApplyExpectations(t, store, tc.storeExpectation...)
			mock.ApplyExpectations(t, wrapper, tc.wrapperExpectation)
			mock.ApplyExpectations(t, transformer, tc.transformerExpectation)

			err := NewController(store, wrapper, transformer).Scan(ctx, tc.scanJobKey, &tc.scanRequest)
			assert.Equal(t, tc.expectedError, err)

			store.AssertExpectations(t)
			wrapper.AssertExpectations(t)
			transformer.AssertExpectations(t)
		})
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
			Name:          "No auth",
			Authorization: "",
			ExpectedAuth:  trivy.NoAuth{},
		},
		{
			Name:          "Basic auth",
			Authorization: "Basic aGFyYm9yOnMzY3JldA==",
			ExpectedAuth: trivy.BasicAuth{
				Username: "harbor",
				Password: "s3cret",
			},
		},
		{
			Name:          "Bearer auth",
			Authorization: "Bearer someToken",
			ExpectedAuth: trivy.BearerAuth{
				Token: "someToken",
			},
		},
		{
			Name:          "Invalid auth",
			Authorization: "Invalid someToken",
			ExpectedAuth:  nil,
			ExpectedError: "unrecognized authorization type: Invalid",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			c := controller{}

			auth, err := c.ToRegistryAuth(tc.Authorization)
			if tc.ExpectedError != "" {
				assert.EqualError(t, err, tc.ExpectedError)
			} else {
				assert.NoError(t, err)
			}

			assert.Equal(t, tc.ExpectedAuth, auth)
		})
	}
}
