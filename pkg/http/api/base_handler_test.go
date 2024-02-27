package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMimeType_String(t *testing.T) {
	testCases := []struct {
		Name           string
		MimeType       MIMEType
		ExpectedString string
	}{
		{
			Name: "A",
			MimeType: MIMEType{
				Type:    "application",
				Subtype: "vnd.scanner.adapter.scan.request+json",
			},
			ExpectedString: "application/vnd.scanner.adapter.scan.request+json",
		},
		{
			Name: "B",
			MimeType: MIMEType{
				Type:    "application",
				Subtype: "vnd.scanner.adapter.scan.request+json",
				Params:  map[string]string{"version": "1.0"},
			},
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
	handler.WriteJSONError(recorder, Error{
		HTTPCode: http.StatusBadRequest,
		Message:  "Invalid request",
	})

	// then
	assert.Equal(t, http.StatusBadRequest, recorder.Code)
	assert.JSONEq(t, `{"error":{"message":"Invalid request"}}`, recorder.Body.String())
}

func TestBaseHandler_SendInternalServerError(t *testing.T) {
	recorder := httptest.NewRecorder()
	handler := &BaseHandler{}

	handler.SendInternalServerError(recorder)

	assert.Equal(t, http.StatusInternalServerError, recorder.Code)
	assert.Equal(t, "Internal Server Error\n", recorder.Body.String())
}
