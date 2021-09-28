//go:build component
// +build component

package scanner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/harbor"
)

// Client is the API client that performs all operations against a Scanner Adapter.
type Client struct {
	endpointURL string
}

// NewClient constructs a new Client with the given Scanner Adapter endpoint URL.
func NewClient(endpointURL string) *Client {
	return &Client{
		endpointURL: strings.TrimRight(endpointURL, "/"),
	}
}

// RequestScan sends a ScanRequest to the Scanner Adapter and receives the corresponding ScanResponse.
// Use the ScanResponse's ID to get the ScanReport or error.
func (c *Client) RequestScan(request harbor.ScanRequest) (scanResp harbor.ScanResponse, err error) {
	url := fmt.Sprintf("%s/%s", c.endpointURL, "api/v1/scan")
	b, err := json.Marshal(request)
	if err != nil {
		return
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(b))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/vnd.security.vulnerability.report; version=1.1")

	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		return
	}

	if resp.StatusCode != http.StatusAccepted {
		return scanResp, fmt.Errorf("invalid response status: %v %v", resp.StatusCode, resp.Status)
	}

	if err = json.NewDecoder(resp.Body).Decode(&scanResp); err != nil {
		return
	}

	return
}

// GetScanReport polls for ScanReport associated with the given ScanRequest ID.
func (c *Client) GetScanReport(scanRequestID string) (report harbor.ScanReport, err error) {
	res, err := c.doGetScanReport(scanRequestID)
	for err == nil && res.StatusCode == http.StatusFound {
		time.Sleep(10 * time.Second)
		res, err = c.doGetScanReport(scanRequestID)
	}
	if err != nil {
		return
	}
	if res.StatusCode != http.StatusOK {
		return report, fmt.Errorf("invalid response status: %s", res.Status)
	}

	if err = json.NewDecoder(res.Body).Decode(&report); err != nil {
		return
	}
	return
}

func (c *Client) doGetScanReport(scanRequestID string) (*http.Response, error) {
	url := fmt.Sprintf("%s/api/v1/scan/%s/report", c.endpointURL, scanRequestID)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.security.vulnerability.report; version=1.1")

	return http.DefaultTransport.RoundTrip(req)
}
