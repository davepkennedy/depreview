# CLAUDE.md — depreview

Persistent context for this project. Read `docs/DESIGN.md` before making
any architectural decision — it captures the reasoning behind choices
below, not just the choices themselves, and several of them look
arbitrary without that reasoning.

## What this is

A CLI that checks a repo's actual dependencies against a human-reviewed
ledger, built to produce evidence for compliance audits (ISO 27001,
SOC 2, DORA) that someone actually reviewed a dependency — not just
that a policy exists. See `docs/DESIGN.md` for the full "why."

## Non-negotiable design principles — do not violate these silently

- **Let git be the database.** No hosted backend, no custom auth, no
  server-side database for v0. The ledger is a YAML file in the repo;
  a merged PR editing it *is* the attestation. Identity comes from
  signed git commits, tamper-evidence from git history, segregation of
  duties from branch protection / GitHub rulesets — not from anything
  this tool builds itself.
- **Human review, AI-assisted — never AI-driven.** Any AI analysis this
  tool ever adds must be framed as a draft or a question for a human to
  engage with, never as a verdict. The human's decision is the artifact
  of record.
- **Solo-buildable.** This is built by one person in spare time. Prefer
  boring, already-solved tools (Syft for SBOM, OSV for advisories) over
  building anything from scratch. If a feature needs a team to operate,
  it's out of scope for now.
- **Defensible claims only.** Don't let the tool (or its docs) claim
  more assurance than it actually provides. It converts "prove no one
  lied" (impossible) into "make claims accountable and detectable"
  (achievable) — never claim the former.

## Current state of the code

- `cmd/depreview` + `internal/{ledger,sbom,osv,compare,report}` — a
  working Go CLI. Builds clean, `gofmt` clean, real unit tests passing
  (fixture-based SBOM parsing test, fake-OSV-client compare tests, a
  `httptest`-backed OSV wire-format test).
- Per-repo ledger at `.depreview/ledger.yaml`: tracks whether the
  dependency version in use matches what was reviewed, and whether OSV
  has published anything new against a version that was already
  approved.
- `.github/workflows/depreview.yml`: runs the check in CI, non-zero
  exit blocks the PR.

## Designed, not yet built — see docs/DESIGN.md for full rationale

- Org-level dependency **catalog** (separate repo from any one
  service's ledger): one entry per dependency *family* (e.g. all of
  `junit-jupiter-api/engine/params` roll up to one "JUnit5" entry), not
  duplicated per repo.
- **Three-group approval** (engineering management, security, legal) on
  catalog entries, via GitHub's ruleset-based "required review by
  specific teams" — plain CODEOWNERS is *not* sufficient here, it's
  satisfied by any one listed team, not all of them.
- **Grandfathering** for pre-existing dependencies when the gate first
  turns on: never permanent, requires a `catch_up_deadline` at creation,
  prioritized by a `materiality` tag (`business-critical` vs
  `internal-tooling`) rather than raw usage count.

## Before adding a feature

Check whether it violates one of the principles above before writing
code. If a request seems to call for a hosted service, a new database,
or an AI verdict-without-human-review, stop and flag the conflict
rather than building around it silently.
