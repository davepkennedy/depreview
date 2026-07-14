// Package report renders compare.Result rows for humans, in CI logs and
// on a terminal. No dashboard, no HTML — just a table, on purpose.
package report

import (
	"fmt"
	"io"
	"text/tabwriter"

	"depreview/internal/compare"
)

// WriteTable prints one row per dependency, aligned into columns.
func WriteTable(w io.Writer, results []compare.Result) {
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "PACKAGE\tECOSYSTEM\tVERSION\tSTATUS\tDETAIL")
	for _, r := range results {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", r.Package, r.Ecosystem, r.Version, r.Status, r.Detail)
	}
	tw.Flush()
}

// Summary counts how many results need attention, for the final
// pass/fail line.
func Summary(results []compare.Result) (total int, needsAttention int) {
	total = len(results)
	for _, r := range results {
		if r.NeedsAttention() {
			needsAttention++
		}
	}
	return total, needsAttention
}
