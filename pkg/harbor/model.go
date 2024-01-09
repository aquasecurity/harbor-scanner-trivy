package harbor

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"time"
)

// Severity represents the severity of a image/component in terms of vulnerability.
type Severity int64

// Sevxxx is the list of severity of image after scanning.
const (
	_ Severity = iota
	SevUnknown
	SevLow
	SevMedium
	SevHigh
	SevCritical
)

func (s Severity) String() string {
	return severityToString[s]
}

var severityToString = map[Severity]string{
	SevUnknown:  "Unknown",
	SevLow:      "Low",
	SevMedium:   "Medium",
	SevHigh:     "High",
	SevCritical: "Critical",
}

var stringToSeverity = map[string]Severity{
	"Unknown":  SevUnknown,
	"Low":      SevLow,
	"Medium":   SevMedium,
	"High":     SevHigh,
	"Critical": SevCritical,
}

// MarshalJSON marshals the Severity enum value as a quoted JSON string.
func (s Severity) MarshalJSON() ([]byte, error) {
	buffer := bytes.NewBufferString(`"`)
	buffer.WriteString(severityToString[s])
	buffer.WriteString(`"`)
	return buffer.Bytes(), nil
}

// UnmarshalJSON unmarshals quoted JSON string to the Severity enum value.
func (s *Severity) UnmarshalJSON(b []byte) error {
	var value string
	err := json.Unmarshal(b, &value)
	if err != nil {
		return err
	}
	*s = stringToSeverity[value]
	return nil
}

type CapabilityType string
type MediaType string

const (
	CapabilityTypeSBOM          CapabilityType = "sbom"
	CapabilityTypeVulnerability CapabilityType = "vulnerability"

	MediaTypeSPDX      MediaType = "application/spdx+json"
	MediaTypeCycloneDX MediaType = "application/vnd.cyclonedx+json"
)

var SupportedSBOMMediaTypes = []MediaType{
	MediaTypeSPDX,
	MediaTypeCycloneDX,
}

type Registry struct {
	URL           string `json:"url"`
	Authorization string `json:"authorization"`
}

type Artifact struct {
	Repository string `json:"repository"`
	Digest     string `json:"digest"`
	MimeType   string `json:"mime_type,omitempty"`
}

type ScanRequest struct {
	Registry     Registry     `json:"registry"`
	Artifact     Artifact     `json:"artifact"`
	Capabilities []Capability `json:"enabled_capabilities"`
}

// GetImageRef returns Docker image reference for this ScanRequest.
// Example: core.harbor.domain/scanners/mysql@sha256:3b00a364fb74246ca119d16111eb62f7302b2ff66d51e373c2bb209f8a1f3b9e
func (c ScanRequest) GetImageRef() (imageRef string, nonSSL bool, err error) {
	registryURL, err := url.Parse(c.Registry.URL)
	if err != nil {
		err = fmt.Errorf("parsing registry URL: %w", err)
		return
	}

	port := registryURL.Port()
	if port == "" && registryURL.Scheme == "http" {
		port = "80"
	}
	if port == "" && registryURL.Scheme == "https" {
		port = "443"
	}

	imageRef = fmt.Sprintf("%s:%s/%s@%s", registryURL.Hostname(), port, c.Artifact.Repository, c.Artifact.Digest)
	nonSSL = "http" == registryURL.Scheme
	return
}

type ScanResponse struct {
	ID string `json:"id"`
}

type ScanReport struct {
	GeneratedAt time.Time `json:"generated_at"`
	Artifact    Artifact  `json:"artifact"`
	Scanner     Scanner   `json:"scanner"`
	Severity    Severity  `json:"severity,omitempty"`

	// For SBOM
	MediaType string `json:"media_type,omitempty"`
	SBOM      any    `json:"sbom,omitempty"`

	// For vulnerabilities
	Vulnerabilities []VulnerabilityItem `json:"vulnerabilities,omitempty"`
}

type Layer struct {
	Digest string `json:"digest,omitempty"`
	DiffID string `json:"diff_id,omitempty"`
}

type CVSSDetails struct {
	ScoreV2  *float32 `json:"score_v2,omitempty"`
	ScoreV3  *float32 `json:"score_v3,omitempty"`
	VectorV2 string   `json:"vector_v2"`
	VectorV3 string   `json:"vector_v3"`
}

// VulnerabilityItem is an item in the vulnerability result returned by vulnerability details API.
type VulnerabilityItem struct {
	ID               string                 `json:"id"`
	Pkg              string                 `json:"package"`
	Version          string                 `json:"version"`
	FixVersion       string                 `json:"fix_version,omitempty"`
	Severity         Severity               `json:"severity"`
	Description      string                 `json:"description"`
	Links            []string               `json:"links"`
	Layer            *Layer                 `json:"layer"` // Not defined by Scanners API
	PreferredCVSS    *CVSSDetails           `json:"preferred_cvss,omitempty"`
	CweIDs           []string               `json:"cwe_ids,omitempty"`
	VendorAttributes map[string]interface{} `json:"vendor_attributes,omitempty"`
}

type ScannerAdapterMetadata struct {
	Scanner      Scanner           `json:"scanner"`
	Capabilities []Capability      `json:"capabilities"`
	Properties   map[string]string `json:"properties"`
}

type Scanner struct {
	Name    string `json:"name"`
	Vendor  string `json:"vendor"`
	Version string `json:"version"`
}

type Capability struct {
	Type              CapabilityType        `json:"type"`
	ConsumesMIMETypes []string              `json:"consumes_mime_types"`
	ProducesMIMETypes []string              `json:"produces_mime_types"`
	Parameters        *CapabilityParameters `json:"parameters,omitempty"`
}

type CapabilityParameters struct {
	MediaType MediaType `json:"accept_media_type,omitempty"`
}

// Error holds the information about an error, including metadata about its JSON structure.
type Error struct {
	HTTPCode int    `json:"-"`
	Message  string `json:"message"`
}
