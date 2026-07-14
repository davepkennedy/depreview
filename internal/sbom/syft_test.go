package sbom

import "testing"

const fixture = `{
  "artifacts": [
    {"name": "lodash", "version": "4.17.21", "type": "npm"},
    {"name": "requests", "version": "2.31.0", "type": "python"},
    {"name": "golang.org/x/text", "version": "v0.14.0", "type": "go-module"},
    {"name": "left-pad", "version": "1.3.0", "type": "some-future-ecosystem"}
  ]
}`

func TestParse(t *testing.T) {
	components, err := Parse([]byte(fixture))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if len(components) != 4 {
		t.Fatalf("expected 4 components, got %d", len(components))
	}

	want := []Component{
		{Name: "lodash", Version: "4.17.21", Ecosystem: "npm"},
		{Name: "requests", Version: "2.31.0", Ecosystem: "PyPI"},
		{Name: "golang.org/x/text", Version: "v0.14.0", Ecosystem: "Go"},
		{Name: "left-pad", Version: "1.3.0", Ecosystem: "some-future-ecosystem"},
	}

	for i, w := range want {
		if components[i] != w {
			t.Errorf("component %d: got %+v, want %+v", i, components[i], w)
		}
	}
}

func TestNormalizeEcosystemFallsBackForUnknownTypes(t *testing.T) {
	got := normalizeEcosystem("cocoapods")
	if got != "cocoapods" {
		t.Errorf("expected unmapped type to pass through unchanged, got %q", got)
	}
}
