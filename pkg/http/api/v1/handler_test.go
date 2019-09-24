package v1

import (
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/model/harbor"
	"github.com/stretchr/testify/assert"
	"net/http"
	"testing"
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
