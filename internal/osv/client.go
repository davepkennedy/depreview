// Package osv queries the OSV.dev vulnerability database
// (https://osv.dev), a free, no-API-key-required, well-maintained feed
// covering npm, PyPI, Go, crates.io, Maven, NuGet and more. This is the
// source for depreview's drift trigger: a dependency whose reviewed
// version now has a published advisory against it needs re-review, even
// though nothing in the repo itself changed.
package osv

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

// DefaultBaseURL is OSV's public API. Overridable on Client for testing
// and for anyone running an internal mirror.
const DefaultBaseURL = "https://api.osv.dev"

// Client queries OSV's batch endpoint.
type Client struct {
	BaseURL    string
	HTTPClient *http.Client
}

// NewClient returns a Client pointed at the public OSV API.
func NewClient() *Client {
	return &Client{
		BaseURL:    DefaultBaseURL,
		HTTPClient: http.DefaultClient,
	}
}

// Query identifies one package+version to check.
type Query struct {
	Name      string
	Ecosystem string
	Version   string
}

// Vuln is the subset of an OSV advisory depreview surfaces. OSV records
// carry far more (affected ranges, references, severity) — v0 only
// needs enough to tell a reviewer "something changed, go look."
type Vuln struct {
	ID      string `json:"id"`
	Summary string `json:"summary,omitempty"`
}

type batchQueryRequest struct {
	Queries []batchQueryEntry `json:"queries"`
}

type batchQueryEntry struct {
	Package batchPackage `json:"package"`
	Version string       `json:"version"`
}

type batchPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type batchQueryResponse struct {
	Results []struct {
		Vulns []Vuln `json:"vulns"`
	} `json:"results"`
}

// QueryBatch checks many package/version pairs in a single request and
// returns, for each input query in the same order, the list of known
// vulnerabilities (empty if none). OSV's batch endpoint returns minimal
// vuln records (mostly just IDs); that's sufficient for depreview to
// flag "N advisories exist" without needing full advisory text in v0.
func (c *Client) QueryBatch(queries []Query) ([][]Vuln, error) {
	if len(queries) == 0 {
		return nil, nil
	}

	req := batchQueryRequest{Queries: make([]batchQueryEntry, len(queries))}
	for i, q := range queries {
		req.Queries[i] = batchQueryEntry{
			Package: batchPackage{Name: q.Name, Ecosystem: q.Ecosystem},
			Version: q.Version,
		}
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("encoding OSV request: %w", err)
	}

	resp, err := c.HTTPClient.Post(c.BaseURL+"/v1/querybatch", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("calling OSV: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV returned %s", resp.Status)
	}

	var out batchQueryResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("parsing OSV response: %w", err)
	}
	if len(out.Results) != len(queries) {
		return nil, fmt.Errorf("OSV returned %d results for %d queries", len(out.Results), len(queries))
	}

	vulns := make([][]Vuln, len(out.Results))
	for i, r := range out.Results {
		vulns[i] = r.Vulns
	}
	return vulns, nil
}
