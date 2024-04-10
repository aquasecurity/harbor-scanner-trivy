package api

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"golang.org/x/xerrors"
)

const (
	HeaderContentType = "Content-Type"
	HeaderAccept      = "Accept"
)

type MimeTypeParams map[string]string
type MediaType string

// Error holds the information about an error, including metadata about its JSON structure.
type Error struct {
	HTTPCode int    `json:"-"`
	Message  string `json:"message"`
}

var (
	MimeTypeVersion = map[string]string{"version": "1.0"}

	MimeTypeOCIImageManifest = MIMEType{
		Type:    "application",
		Subtype: "vnd.oci.image.manifest.v1+json",
	}
	MimeTypeDockerImageManifestV2 = MIMEType{
		Type:    "application",
		Subtype: "vnd.docker.distribution.manifest.v2+json",
	}
	MimeTypeScanResponse = MIMEType{
		Type:    "application",
		Subtype: "vnd.scanner.adapter.scan.response+json",
		Params:  MimeTypeVersion,
	}
	MimeTypeSecurityVulnerabilityReport = MIMEType{
		Type:    "application",
		Subtype: "vnd.security.vulnerability.report",
		Params:  map[string]string{"version": "1.1"},
	}
	MimeTypeSecuritySBOMReport = MIMEType{
		Type:    "application",
		Subtype: "vnd.security.sbom.report+json",
		Params:  map[string]string{"version": "1.0"},
	}
	MimeTypeMetadata = MIMEType{
		Type:    "application",
		Subtype: "vnd.scanner.adapter.metadata+json",
		Params:  MimeTypeVersion,
	}
	MimeTypeError = MIMEType{
		Type:    "application",
		Subtype: "vnd.scanner.adapter.error",
		Params:  MimeTypeVersion,
	}

	MediaTypeSPDX      MediaType = "application/spdx+json"
	MediaTypeCycloneDX MediaType = "application/vnd.cyclonedx+json"
)

type MIMEType struct {
	Type    string
	Subtype string
	Params  MimeTypeParams
}

func (mt MIMEType) MarshalJSON() ([]byte, error) {
	return json.Marshal(mt.String())
}

func (mt *MIMEType) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	return mt.Parse(s)
}

func (mt *MIMEType) String() string {
	if mt.Type == "" || mt.Subtype == "" {
		return ""
	}
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

func (mt *MIMEType) Parse(value string) error {
	switch value {
	case "", "*/*", MimeTypeSecurityVulnerabilityReport.String():
		mt.Type = MimeTypeSecurityVulnerabilityReport.Type
		mt.Subtype = MimeTypeSecurityVulnerabilityReport.Subtype
		mt.Params = MimeTypeSecurityVulnerabilityReport.Params
		return nil
	case MimeTypeSecuritySBOMReport.String():
		mt.Type = MimeTypeSecuritySBOMReport.Type
		mt.Subtype = MimeTypeSecuritySBOMReport.Subtype
		mt.Params = MimeTypeSecuritySBOMReport.Params
		return nil
	}
	return xerrors.Errorf("unsupported mime type: %s", value)
}

func (mt *MIMEType) Equal(other MIMEType) bool {
	if mt.Type != other.Type || mt.Subtype != other.Subtype || len(mt.Params) != len(other.Params) {
		return false
	}
	for k, v := range mt.Params {
		if other.Params[k] != v {
			return false
		}
	}
	return true
}

type BaseHandler struct {
}

func (h *BaseHandler) WriteJSON(res http.ResponseWriter, data interface{}, mimeType MIMEType, statusCode int) {
	res.Header().Set(HeaderContentType, mimeType.String())
	res.WriteHeader(statusCode)

	err := json.NewEncoder(res).Encode(data)
	if err != nil {
		slog.Error("Error while writing JSON", slog.String("err", err.Error()))
		h.SendInternalServerError(res)
		return
	}
}

func (h *BaseHandler) WriteJSONError(res http.ResponseWriter, err Error) {
	data := struct {
		Err Error `json:"error"`
	}{err}

	h.WriteJSON(res, data, MimeTypeError, err.HTTPCode)
}

func (h *BaseHandler) SendInternalServerError(res http.ResponseWriter) {
	http.Error(res, "Internal Server Error", http.StatusInternalServerError)
}
