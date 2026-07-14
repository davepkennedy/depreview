// Package ledger reads and writes the human-reviewed dependency ledger.
//
// The ledger is a plain YAML file committed inside the repository it
// protects. A PR that edits it, reviewed and merged through the repo's
// normal process, *is* the attestation — there is no separate database,
// no auth system, and no server. Identity and tamper-evidence come from
// git itself (signed commits, branch protection requiring a second
// approver), not from anything this package does. This package only
// knows how to read and write the file.
package ledger

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Decision is the reviewer's verdict on a dependency.
type Decision string

const (
	DecisionApproved Decision = "approved"
	DecisionFlagged  Decision = "flagged"
	DecisionRejected Decision = "rejected"
)

// Entry is one reviewed dependency, at the version it was reviewed at.
//
// Version is the exact version the reviewer looked at. If the manifest
// later reports a different version for the same package, that's drift,
// and the entry no longer covers what's actually in use — see
// compare.Compare.
type Entry struct {
	Package    string   `yaml:"package"`
	Ecosystem  string   `yaml:"ecosystem"`
	Version    string   `yaml:"version"`
	License    string   `yaml:"license,omitempty"`
	Decision   Decision `yaml:"decision"`
	ReviewedBy string   `yaml:"reviewed_by,omitempty"`
	ReviewedAt string   `yaml:"reviewed_at,omitempty"` // YYYY-MM-DD
	Rationale  string   `yaml:"rationale,omitempty"`
}

// Ledger is the full set of reviewed dependencies for a repo.
type Ledger struct {
	Reviews []Entry `yaml:"reviews"`
}

// Key uniquely identifies a dependency regardless of version, since the
// same name can exist in more than one ecosystem.
func (e Entry) Key() string {
	return e.Ecosystem + "/" + e.Package
}

// Index builds a lookup from Key() to Entry for fast comparison against
// an SBOM. If the ledger somehow has duplicate keys, the last one wins —
// callers should treat that as a lint warning, not silently accept it.
func (l *Ledger) Index() map[string]Entry {
	idx := make(map[string]Entry, len(l.Reviews))
	for _, e := range l.Reviews {
		idx[e.Key()] = e
	}
	return idx
}

// Load reads a ledger file from disk. A missing file is not an error —
// it just means nothing has been reviewed yet, which is a legitimate
// (if unimpressive) starting state.
func Load(path string) (*Ledger, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &Ledger{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading ledger %s: %w", path, err)
	}

	var l Ledger
	if err := yaml.Unmarshal(data, &l); err != nil {
		return nil, fmt.Errorf("parsing ledger %s: %w", path, err)
	}
	return &l, nil
}

// Save writes the ledger back to disk, sorted by ecosystem then package
// so that diffs in the PR that edits it stay small and reviewable.
func Save(path string, l *Ledger) error {
	data, err := yaml.Marshal(l)
	if err != nil {
		return fmt.Errorf("encoding ledger: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("writing ledger %s: %w", path, err)
	}
	return nil
}
