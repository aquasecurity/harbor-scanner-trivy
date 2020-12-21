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
	HeaderAccept      = "Accept"
)

type MimeTypeParams map[string]string

var MimeTypeVersion = map[string]string{"version": "1.0"}

var MimeTypeOCIImageManifest = MimeType{Type: "application", Subtype: "vnd.oci.image.manifest.v1+json"}
var MimeTypeDockerImageManifestV2 = MimeType{Type: "application", Subtype: "vnd.docker.distribution.manifest.v2+json"}

var MimeTypeScanResponse = MimeType{Type: "application", Subtype: "vnd.scanner.adapter.scan.response+json", Params: MimeTypeVersion}

// Deprecated
var MimeTypeHarborVulnerabilityReport = MimeType{Type: "application", Subtype: "vnd.scanner.adapter.vuln.report.harbor+json", Params: MimeTypeVersion}
var MimeTypeSecurityVulnerabilityReport = MimeType{Type: "application", Subtype: "vnd.security.vulnerability.report", Params: map[string]string{"version": "1.1"}}
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

func (mt *MimeType) FromAcceptHeader(value string) error {
	switch value {
	case "", "*/*", MimeTypeHarborVulnerabilityReport.String():
		mt.Type = MimeTypeHarborVulnerabilityReport.Type
		mt.Subtype = MimeTypeHarborVulnerabilityReport.Subtype
		mt.Params = MimeTypeHarborVulnerabilityReport.Params
		return nil
	case MimeTypeSecurityVulnerabilityReport.String():
		mt.Type = MimeTypeSecurityVulnerabilityReport.Type
		mt.Subtype = MimeTypeSecurityVulnerabilityReport.Subtype
		mt.Params = MimeTypeSecurityVulnerabilityReport.Params
		return nil
	}
	return fmt.Errorf("unsupported mime type: %s", value)
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
