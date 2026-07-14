// Package compare implements depreview's core rule: for every dependency
// actually in use, is there a human attestation that covers exactly this
// version, and has anything happened since that attestation was written
// that should invalidate it?
package compare

import (
	"fmt"

	"depreview/internal/ledger"
	"depreview/internal/osv"
	"depreview/internal/sbom"
)

// Status is the outcome of comparing one in-use dependency against the
// ledger and the live advisory feed.
type Status string

const (
	// StatusOK: reviewed, version matches, no new advisories since review.
	StatusOK Status = "OK"
	// StatusNew: this dependency has no ledger entry at all.
	StatusNew Status = "NEEDS REVIEW (new)"
	// StatusDrifted: it's in the ledger, but the version in use has moved
	// on from the version that was reviewed.
	StatusDrifted Status = "NEEDS REVIEW (drifted)"
	// StatusAdvisory: version matches what was reviewed, but OSV now
	// lists an advisory that didn't exist (or wasn't known) at review time.
	StatusAdvisory Status = "NEEDS RE-REVIEW (advisory)"
)

// Result is one row of the report: an in-use dependency and its status.
type Result struct {
	Package   string
	Ecosystem string
	Version   string
	Status    Status
	Detail    string
}

// NeedsAttention reports whether this result should fail a CI check.
func (r Result) NeedsAttention() bool {
	return r.Status != StatusOK
}

// osvQuerier is the subset of *osv.Client that Run depends on, so tests
// can supply a fake without spinning up an HTTP server.
type osvQuerier interface {
	QueryBatch(queries []osv.Query) ([][]osv.Vuln, error)
}

// Run compares live components against the ledger. It only calls out to
// OSV for dependencies that are already reviewed and version-matched —
// new or drifted dependencies are flagged regardless of advisories,
// since they need a human look either way, and there's no point
// spending an API call to tell you that.
func Run(components []sbom.Component, l *ledger.Ledger, osvClient osvQuerier) ([]Result, error) {
	idx := l.Index()

	results := make([]Result, 0, len(components))
	var toQuery []osv.Query
	var toQueryIdx []int // index into results, filled in after the OSV call

	for _, c := range components {
		key := c.Ecosystem + "/" + c.Name
		entry, reviewed := idx[key]

		r := Result{
			Package:   c.Name,
			Ecosystem: c.Ecosystem,
			Version:   c.Version,
		}

		switch {
		case !reviewed:
			r.Status = StatusNew
			r.Detail = "no ledger entry"
		case entry.Version != c.Version:
			r.Status = StatusDrifted
			r.Detail = fmt.Sprintf("reviewed %s, now %s", entry.Version, c.Version)
		default:
			// Version matches what was reviewed — defer the verdict
			// until we know whether OSV has anything new to say.
			r.Status = StatusOK
			r.Detail = fmt.Sprintf("reviewed %s by %s", entry.ReviewedAt, entry.ReviewedBy)
			toQuery = append(toQuery, osv.Query{Name: c.Name, Ecosystem: c.Ecosystem, Version: c.Version})
			toQueryIdx = append(toQueryIdx, len(results))
		}

		results = append(results, r)
	}

	if len(toQuery) == 0 {
		return results, nil
	}

	vulnLists, err := osvClient.QueryBatch(toQuery)
	if err != nil {
		return nil, fmt.Errorf("checking OSV: %w", err)
	}

	for i, vulns := range vulnLists {
		if len(vulns) == 0 {
			continue
		}
		ri := toQueryIdx[i]
		results[ri].Status = StatusAdvisory
		results[ri].Detail = fmt.Sprintf("%d advisory(ies), e.g. %s", len(vulns), vulns[0].ID)
	}

	return results, nil
}
