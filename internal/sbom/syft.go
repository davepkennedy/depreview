// Package sbom generates and parses a software bill of materials.
//
// Generation is delegated entirely to Syft (https://github.com/anchore/syft)
// via the CLI — this package does not implement its own dependency
// scanner. Syft already knows how to walk npm, pip, cargo, go modules,
// maven, nuget and more; reimplementing that would be a lot of fragile
// work for something already solved well. This package's only job is to
// run it and parse out the handful of fields depreview actually needs.
package sbom

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
)

// Component is one dependency found in the target repo, normalized down
// to what the rest of depreview cares about.
type Component struct {
	Name      string
	Version   string
	Ecosystem string
}

// syftDocument is a partial view of Syft's native JSON output. Syft's
// real schema has many more fields (locations, layers, licenses,
// metadata per package type); encoding/json ignores anything we don't
// name here, so this struct only lists what we read.
type syftDocument struct {
	Artifacts []syftArtifact `json:"artifacts"`
}

type syftArtifact struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Type    string `json:"type"` // syft's package type, e.g. "npm", "python", "go-module"
}

// ecosystemNames maps Syft's internal package type strings to the
// ecosystem names OSV expects (https://ossf.github.io/osv-schema/#affectedpackage-field).
// Extend this as more ecosystems come up in practice — an unmapped type
// falls back to the raw Syft string, which will simply fail to match
// anything in OSV and get flagged for review, which is the safe default.
var ecosystemNames = map[string]string{
	"npm":          "npm",
	"python":       "PyPI",
	"go-module":    "Go",
	"rust-crate":   "crates.io",
	"java-archive": "Maven",
	"dotnet":       "NuGet",
}

func normalizeEcosystem(syftType string) string {
	if name, ok := ecosystemNames[syftType]; ok {
		return name
	}
	return syftType
}

// Run shells out to the syft binary against the given path and returns
// its raw JSON output. It expects "syft" to already be on PATH; that's
// a deliberate choice for v0 — installing/managing the Syft binary is
// left to the CI environment (a single `curl | sh` line, or the
// anchore/sbom-action if this becomes a GitHub Action later) rather
// than this tool trying to vendor or auto-install it.
func Run(path string) ([]byte, error) {
	cmd := exec.Command("syft", path, "-o", "json")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("running syft (is it installed and on PATH?): %w: %s", err, stderr.String())
	}
	return stdout.Bytes(), nil
}

// Parse decodes Syft's JSON output into the Components depreview needs.
func Parse(data []byte) ([]Component, error) {
	var doc syftDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parsing syft output: %w", err)
	}

	components := make([]Component, 0, len(doc.Artifacts))
	for _, a := range doc.Artifacts {
		components = append(components, Component{
			Name:      a.Name,
			Version:   a.Version,
			Ecosystem: normalizeEcosystem(a.Type),
		})
	}
	return components, nil
}

// Generate runs syft against path and returns the parsed component list
// in one step.
func Generate(path string) ([]Component, error) {
	data, err := Run(path)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}
