package compare

import (
	"testing"

	"depreview/internal/ledger"
	"depreview/internal/osv"
	"depreview/internal/sbom"
)

// fakeOSV lets tests control exactly which queries come back with
// advisories, without any network access.
type fakeOSV struct {
	// vulnByKey maps "ecosystem/name@version" to the vulns to return.
	vulnByKey map[string][]osv.Vuln
}

func (f *fakeOSV) QueryBatch(queries []osv.Query) ([][]osv.Vuln, error) {
	out := make([][]osv.Vuln, len(queries))
	for i, q := range queries {
		key := q.Ecosystem + "/" + q.Name + "@" + q.Version
		out[i] = f.vulnByKey[key]
	}
	return out, nil
}

func testLedger() *ledger.Ledger {
	return &ledger.Ledger{
		Reviews: []ledger.Entry{
			{
				Package: "lodash", Ecosystem: "npm", Version: "4.17.21",
				Decision: ledger.DecisionApproved, ReviewedBy: "dave", ReviewedAt: "2026-01-15",
			},
			{
				Package: "requests", Ecosystem: "PyPI", Version: "2.30.0",
				Decision: ledger.DecisionApproved, ReviewedBy: "dave", ReviewedAt: "2026-02-01",
			},
		},
	}
}

func TestRun_NewDependencyIsFlagged(t *testing.T) {
	components := []sbom.Component{
		{Name: "left-pad", Version: "1.3.0", Ecosystem: "npm"},
	}
	results, err := Run(components, testLedger(), &fakeOSV{})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if results[0].Status != StatusNew {
		t.Errorf("expected StatusNew, got %s (%s)", results[0].Status, results[0].Detail)
	}
}

func TestRun_DriftedVersionIsFlagged(t *testing.T) {
	components := []sbom.Component{
		// reviewed at 2.30.0, manifest now says 2.31.0
		{Name: "requests", Version: "2.31.0", Ecosystem: "PyPI"},
	}
	results, err := Run(components, testLedger(), &fakeOSV{})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if results[0].Status != StatusDrifted {
		t.Errorf("expected StatusDrifted, got %s (%s)", results[0].Status, results[0].Detail)
	}
}

func TestRun_MatchedVersionWithNoAdvisoriesIsOK(t *testing.T) {
	components := []sbom.Component{
		{Name: "lodash", Version: "4.17.21", Ecosystem: "npm"},
	}
	results, err := Run(components, testLedger(), &fakeOSV{})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if results[0].Status != StatusOK {
		t.Errorf("expected StatusOK, got %s (%s)", results[0].Status, results[0].Detail)
	}
	if results[0].NeedsAttention() {
		t.Errorf("StatusOK should not need attention")
	}
}

func TestRun_MatchedVersionWithNewAdvisoryIsFlagged(t *testing.T) {
	components := []sbom.Component{
		{Name: "lodash", Version: "4.17.21", Ecosystem: "npm"},
	}
	fake := &fakeOSV{
		vulnByKey: map[string][]osv.Vuln{
			"npm/lodash@4.17.21": {{ID: "GHSA-fake-1234"}},
		},
	}
	results, err := Run(components, testLedger(), fake)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if results[0].Status != StatusAdvisory {
		t.Errorf("expected StatusAdvisory, got %s (%s)", results[0].Status, results[0].Detail)
	}
	if !results[0].NeedsAttention() {
		t.Errorf("StatusAdvisory should need attention")
	}
}

func TestRun_OnlyQueriesOSVForVersionMatchedEntries(t *testing.T) {
	// left-pad is new and requests has drifted — neither should trigger
	// a meaningful OSV lookup, since both are flagged regardless of
	// advisories. The fake returns an empty slice for unrecognized keys
	// (a nil map read is safe in Go), so this mainly documents intent.
	components := []sbom.Component{
		{Name: "left-pad", Version: "1.3.0", Ecosystem: "npm"},
		{Name: "requests", Version: "2.31.0", Ecosystem: "PyPI"},
	}
	fake := &fakeOSV{}
	results, err := Run(components, testLedger(), fake)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if results[0].Status != StatusNew || results[1].Status != StatusDrifted {
		t.Errorf("unexpected statuses: %s, %s", results[0].Status, results[1].Status)
	}
}
