// Command depreview checks a repo's actual dependencies against a
// human-reviewed ledger, and flags anything new, drifted, or newly
// vulnerable since it was last signed off.
//
// Usage:
//
//	depreview -path . -ledger .depreview/ledger.yaml
//
// Exit code is 0 if every dependency is clean, 1 if anything needs
// attention — that makes it a usable CI gate on its own, with no extra
// plumbing.
package main

import (
	"flag"
	"fmt"
	"os"

	"depreview/internal/compare"
	"depreview/internal/ledger"
	"depreview/internal/osv"
	"depreview/internal/report"
	"depreview/internal/sbom"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	fs := flag.NewFlagSet("depreview", flag.ContinueOnError)
	path := fs.String("path", ".", "path to the repository to scan")
	ledgerPath := fs.String("ledger", ".depreview/ledger.yaml", "path to the ledger file")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	components, err := sbom.Generate(*path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error generating SBOM:", err)
		return 1
	}

	l, err := ledger.Load(*ledgerPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error loading ledger:", err)
		return 1
	}

	results, err := compare.Run(components, l, osv.NewClient())
	if err != nil {
		fmt.Fprintln(os.Stderr, "error comparing against OSV:", err)
		return 1
	}

	report.WriteTable(os.Stdout, results)

	total, needsAttention := report.Summary(results)
	fmt.Printf("\n%d dependencies checked, %d need attention\n", total, needsAttention)

	if needsAttention > 0 {
		return 1
	}
	return 0
}
