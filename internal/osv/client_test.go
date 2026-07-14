package osv

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClient_QueryBatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/querybatch" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		var got batchQueryRequest
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("server failed to decode request: %v", err)
		}
		if len(got.Queries) != 2 {
			t.Fatalf("expected 2 queries, got %d", len(got.Queries))
		}
		if got.Queries[0].Package.Name != "lodash" || got.Queries[0].Version != "4.17.21" {
			t.Errorf("unexpected first query: %+v", got.Queries[0])
		}

		// First query (lodash) has an advisory, second (left-pad) doesn't.
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(batchQueryResponse{
			Results: []struct {
				Vulns []Vuln `json:"vulns"`
			}{
				{Vulns: []Vuln{{ID: "GHSA-fake-0001", Summary: "test advisory"}}},
				{Vulns: nil},
			},
		})
	}))
	defer srv.Close()

	client := &Client{BaseURL: srv.URL, HTTPClient: srv.Client()}
	got, err := client.QueryBatch([]Query{
		{Name: "lodash", Ecosystem: "npm", Version: "4.17.21"},
		{Name: "left-pad", Ecosystem: "npm", Version: "1.3.0"},
	})
	if err != nil {
		t.Fatalf("QueryBatch returned error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 results, got %d", len(got))
	}
	if len(got[0]) != 1 || got[0][0].ID != "GHSA-fake-0001" {
		t.Errorf("expected one advisory for lodash, got %+v", got[0])
	}
	if len(got[1]) != 0 {
		t.Errorf("expected no advisories for left-pad, got %+v", got[1])
	}
}

func TestClient_QueryBatch_EmptyInput(t *testing.T) {
	client := NewClient()
	got, err := client.QueryBatch(nil)
	if err != nil {
		t.Fatalf("expected no error for empty input, got %v", err)
	}
	if got != nil {
		t.Errorf("expected nil result for empty input, got %+v", got)
	}
}
