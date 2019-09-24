package harbor

// Sevxxx is the list of severity of image after scanning.
const (
	_ Severity = iota
	SevNone
	SevUnknown
	SevLow
	SevMedium
	SevHigh
)

type Registry struct {
	URL           string `json:"url"`
	Authorization string `json:"authorization"`
}

type Artifact struct {
	Repository string `json:"repository"`
	Digest     string `json:"digest"`
}

type ScanRequest struct {
	Registry Registry `json:"registry"`
	Artifact Artifact `json:"artifact"`
}

type ScanResponse struct {
	ID string `json:"id"`
}

type ScanResult struct {
	Severity        Severity            `json:"severity"`
	Overview        *ComponentsOverview `json:"overview"`
	Vulnerabilities []VulnerabilityItem `json:"vulnerabilities"`
}

// Severity represents the severity of a image/component in terms of vulnerability.
type Severity int64

// ComponentsOverview has the total number and a list of components number of different serverity level.
type ComponentsOverview struct {
	Total   int                        `json:"total"`
	Summary []*ComponentsOverviewEntry `json:"summary"`
}

// ComponentsOverviewEntry ...
type ComponentsOverviewEntry struct {
	Sev   int `json:"severity"`
	Count int `json:"count"`
}

// VulnerabilityItem is an item in the vulnerability result returned by vulnerability details API.
type VulnerabilityItem struct {
	ID          string   `json:"id"`
	Severity    Severity `json:"severity"`
	Pkg         string   `json:"package"`
	Version     string   `json:"version"`
	Description string   `json:"description"`
	Links       []string `json:"links"`
	Fixed       string   `json:"fixedVersion,omitempty"`
}

// Error holds the information about an error, including metadata about its JSON structure.
type Error struct {
	HTTPCode int    `json:"-"`
	Message  string `json:"message"`
}
