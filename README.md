# depreview

A small CLI that checks whether a repo's actual dependencies match what a
human has actually reviewed — and flags the ones that don't, whether
that's because they're new, because the version has drifted since
review, or because a vulnerability advisory has been published against
a version that was already signed off.

## Why this exists

Compliance frameworks (ISO 27001, SOC 2) increasingly expect proof that
someone actually looked at your dependencies, not just that a list of
them exists. An SBOM on its own is a list. What auditors are starting to
ask for is evidence that a named person reviewed it — and most "black
box" compliance tooling can show a green tick for having a policy, but
can't show that a review actually happened against actual code.

This tool doesn't try to solve that with a hosted dashboard or its own
database. It leans entirely on git:

- **The ledger is a YAML file committed in the repo**
  (`.depreview/ledger.yaml`), not a row in someone's SaaS database.
- **A PR that edits the ledger, reviewed and merged, is the
  attestation.** There's no separate UI to fill in.
- **Identity comes from git**: sign your commits, and GitHub will show
  the reviewer's verified identity against the ledger change itself.
- **Tamper-evidence comes from git history**: it's already an
  append-only hash chain.
- **Segregation of duties comes from branch protection**: require a
  second approver on changes to the ledger file, same as any other
  protected path.

depreview's only job is to notice when the ledger and reality have
diverged, and say so loudly enough to fail a CI check.

## How it decides what to flag

For every dependency actually in use (found via a live SBOM, generated
by [Syft](https://github.com/anchore/syft)):

| Situation | Status |
|---|---|
| No ledger entry exists for it | `NEEDS REVIEW (new)` |
| Ledger entry exists, but the version in use doesn't match the version that was reviewed | `NEEDS REVIEW (drifted)` |
| Ledger entry exists, version matches, but [OSV](https://osv.dev) now lists an advisory against it | `NEEDS RE-REVIEW (advisory)` |
| Ledger entry exists, version matches, no new advisories | `OK` |

OSV is only queried for dependencies that are already reviewed and
version-matched — a new or drifted dependency needs a human look
regardless of whether it happens to have a CVE, so there's no point
spending the API call.

## Usage

```sh
go build -o depreview ./cmd/depreview
./depreview -path . -ledger .depreview/ledger.yaml
```

Exit code is `0` if everything's clean, `1` if anything needs attention
— so it works as a CI gate with no extra wiring. See
`.github/workflows/depreview.yml` for a ready-to-use GitHub Actions job.

### Requirements

- [Syft](https://github.com/anchore/syft) on `PATH`. Not vendored or
  auto-installed by this tool on purpose — install it however fits your
  environment (the workflow example uses their official install
  script).
- No API key needed for OSV; it's a free, public API.

### First-time setup

```sh
go mod tidy    # fetches gopkg.in/yaml.v3
```

There's no build step beyond that — it's a single static Go binary.

## What this deliberately doesn't do yet

- **No AI-assisted review or function-level code reading.** This v0 is
  scoped to the dependency ledger only, which is the smaller and more
  mechanical of the two ideas this project grew out of — see
  `docs/` (if you're reading this after adding design notes) for the
  fuller picture.
- **No hosted dashboard or cross-repo aggregation.** Everything lives
  and runs inside the repo it's protecting.
- **No cryptographic signing beyond what git already gives you.**
  Sigstore/Rekor-based signing of the ledger state is a reasonable v1
  addition once a real auditor asks "how do I know this wasn't faked"
  — not a day-one requirement.

## Project layout

```
cmd/depreview/        CLI entrypoint
internal/sbom/         shells out to Syft, parses its JSON output
internal/ledger/       loads/saves .depreview/ledger.yaml
internal/osv/          client for the OSV.dev vulnerability API
internal/compare/       the actual flagging rules
internal/report/       plain-text table output
.depreview/ledger.yaml  the ledger itself — starts empty
.github/workflows/      example CI wiring
```
