package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/harbor"
	log "github.com/sirupsen/logrus"
)

const (
	HeaderContentType = "Content-Type"
)

type MimeTypeParams map[string]string

var MimeTypeVersion = map[string]string{"version": "1.0"}

var MimeTypeOCIImageManifest = MimeType{Type: "application", Subtype: "vnd.oci.image.manifest.v1+json"}
var MimeTypeDockerImageManifest = MimeType{Type: "application", Subtype: "vnd.docker.distribution.manifest.v2+json"}

var MimeTypeScanResponse = MimeType{Type: "application", Subtype: "vnd.scanner.adapter.scan.response+json", Params: MimeTypeVersion}
var MimeTypeHarborVulnerabilityReport = MimeType{Type: "application", Subtype: "vnd.scanner.adapter.vuln.report.harbor+json", Params: MimeTypeVersion}
var MimeTypeMetadata = MimeType{Type: "application", Subtype: "vnd.scanner.adapter.metadata+json", Params: MimeTypeVersion}
var MimeTypeError = MimeType{Type: "application", Subtype: "vnd.scanner.adapter.error", Params: MimeTypeVersion}

type MimeType struct {
	Type    string
	Subtype string
	Params  MimeTypeParams
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
