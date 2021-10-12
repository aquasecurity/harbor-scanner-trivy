package scan

import (
	"fmt"
	"testing"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/harbor"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/job"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/mock"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/trivy"
	"github.com/stretchr/testify/assert"
	"golang.org/x/xerrors"
)

func TestController_Scan(t *testing.T) {
	artifact := harbor.Artifact{
		Repository: "library/mongo",
		Digest:     "sha256:917f5b7f4bef1b35ee90f03033f33a81002511c1e0767fd44276d4bd9cd2fa8e",
	}
	trivyReport := []trivy.Vulnerability{}
	harborReport := harbor.ScanReport{}

	testCases := []struct {
		name string

		scanJobID              string
		scanRequest            harbor.ScanRequest
		storeExpectation       []*mock.Expectation
		wrapperExpectation     *mock.Expectation
		transformerExpectation *mock.Expectation

		expectedError error
	}{
		{
			name:      fmt.Sprintf("Should update job status to %s when everything is fine", job.Finished.String()),
			scanJobID: "job:123",
			scanRequest: harbor.ScanRequest{
				Registry: harbor.Registry{
					URL:           "https://core.harbor.domain",
					Authorization: "Basic dXNlcjpwYXNzd29yZA==", // user:password
				},
				Artifact: artifact,
			},
			storeExpectation: []*mock.Expectation{
				{
					Method:     "UpdateStatus",
					Args:       []interface{}{"job:123", job.Pending, []string(nil)},
					ReturnArgs: []interface{}{nil},
				},
				{
					Method:     "UpdateReport",
					Args:       []interface{}{"job:123", harborReport},
					ReturnArgs: []interface{}{nil},
				},
				{
					Method:     "UpdateStatus",
					Args:       []interface{}{"job:123", job.Finished, []string(nil)},
					ReturnArgs: []interface{}{nil},
				},
			},
			wrapperExpectation: &mock.Expectation{
				Method: "Scan",
				Args: []interface{}{
					trivy.ImageRef{
						Name:     "core.harbor.domain:443/library/mongo@sha256:917f5b7f4bef1b35ee90f03033f33a81002511c1e0767fd44276d4bd9cd2fa8e",
						Auth:     trivy.BasicAuth{Username: "user", Password: "password"},
						Insecure: false,
					},
				},
				ReturnArgs: []interface{}{
					trivyReport,
					nil,
				},
			},
			transformerExpectation: &mock.Expectation{
				Method: "Transform",
				Args: []interface{}{
					artifact,
					trivyReport,
				},
				ReturnArgs: []interface{}{
					harborReport,
				},
			},
		},
		{
			name:      fmt.Sprintf("Should update job status to %s when Trivy wrapper fails", job.Failed.String()),
			scanJobID: "job:123",
			scanRequest: harbor.ScanRequest{
				Registry: harbor.Registry{
					URL:           "https://core.harbor.domain",
					Authorization: "Basic dXNlcjpwYXNzd29yZA==", // user:password
				},
				Artifact: artifact,
			},
			storeExpectation: []*mock.Expectation{
				{
					Method:     "UpdateStatus",
					Args:       []interface{}{"job:123", job.Pending, []string(nil)},
					ReturnArgs: []interface{}{nil},
				},
				{
					Method:     "UpdateStatus",
					Args:       []interface{}{"job:123", job.Failed, []string{"running trivy wrapper: out of memory"}},
					ReturnArgs: []interface{}{nil},
				},
			},
			wrapperExpectation: &mock.Expectation{
				Method: "Scan",
				Args: []interface{}{
					trivy.ImageRef{
						Name:     "core.harbor.domain:443/library/mongo@sha256:917f5b7f4bef1b35ee90f03033f33a81002511c1e0767fd44276d4bd9cd2fa8e",
						Auth:     trivy.BasicAuth{Username: "user", Password: "password"},
						Insecure: false,
					},
				},
				ReturnArgs: []interface{}{
					[]trivy.Vulnerability{},
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

			err := NewController(store, wrapper, transformer).Scan(tc.scanJobID, tc.scanRequest)
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
