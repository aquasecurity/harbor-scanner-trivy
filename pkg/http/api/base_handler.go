package api

import (
	"encoding/json"
	"fmt"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/model/harbor"
	log "github.com/sirupsen/logrus"
	"net/http"
	"strings"
)

const (
	HeaderContentType = "Content-Type"
)

var MimeTypeScanResponse = MimeType{Type: "application", Subtype: "vnd.scanner.adapter.scan.response+json", Params: map[string]string{"version": "1.0"}}
var MimeTypeError = MimeType{Type: "application", Subtype: "vnd.scanner.adapter.error", Params: map[string]string{"version": "1.0"}}

type MimeType struct {
	Type    string
	Subtype string
	Params  map[string]string
}

func (mt MimeType) String() string {
	s := fmt.Sprintf("%s/%s", mt.Type, mt.Subtype)
	if len(mt.Params) == 0 {
		return s
	}
	params := make([]string, 0, len(mt.Params))
	for k, v := range mt.Params {
		params = append(params, fmt.Sprintf("%s=%s", k, v))
	}
	return fmt.Sprintf("%s; %s", s, strings.Join(params, ";"))
}

type BaseHandler struct {
}

func (h *BaseHandler) WriteJSON(res http.ResponseWriter, data interface{}, mimeType MimeType, statusCode int) {
	res.Header().Set(HeaderContentType, mimeType.String())
	res.WriteHeader(statusCode)

	err := json.NewEncoder(res).Encode(data)
	if err != nil {
		log.WithError(err).Error("Error while writing JSON")
		h.SendInternalServerError(res)
		return
	}
}

func (h *BaseHandler) WriteJSONError(res http.ResponseWriter, err harbor.Error) {
	data := struct {
		Err harbor.Error `json:"error"`
	}{err}

	h.WriteJSON(res, data, MimeTypeError, err.HTTPCode)
}

func (h *BaseHandler) SendInternalServerError(res http.ResponseWriter) {
	http.Error(res, "Internal Server Error", http.StatusInternalServerError)
}
