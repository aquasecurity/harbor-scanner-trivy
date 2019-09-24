package api

import (
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/model/harbor"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMimeType_String(t *testing.T) {
	testCases := []struct {
		Name           string
		MimeType       MimeType
		ExpectedString string
	}{
		{
			Name:           "A",
			MimeType:       MimeType{Type: "application", Subtype: "vnd.scanner.adapter.scan.request+json"},
			ExpectedString: "application/vnd.scanner.adapter.scan.request+json",
		},
		{
			Name:           "B",
			MimeType:       MimeType{Type: "application", Subtype: "vnd.scanner.adapter.scan.request+json", Params: map[string]string{"version": "1.0"}},
			ExpectedString: "application/vnd.scanner.adapter.scan.request+json; version=1.0",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			assert.Equal(t, tc.ExpectedString, tc.MimeType.String())
		})
	}
}

func TestBaseHandler_WriteJSONError(t *testing.T) {
	// given
	recorder := httptest.NewRecorder()
	handler := &BaseHandler{}

	// when
	handler.WriteJSONError(recorder, harbor.Error{
		HTTPCode: http.StatusBadRequest,
		Message:  "Invalid request",
	})

	// then
	assert.Equal(t, http.StatusBadRequest, recorder.Code)
	assert.JSONEq(t, `{"error":{"message":"Invalid request"}}`, recorder.Body.String())
}
