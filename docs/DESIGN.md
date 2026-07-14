# depreview — design history and rationale

This is the fuller reasoning behind `CLAUDE.md`. It exists because
several decisions in this project look arbitrary in isolation and only
make sense against the path that led to them — most of that path was a
series of corrections against an initial idea that was too broad, too
orthogonal to any real buyer, or duplicated across scopes it shouldn't
have been.

## How the idea evolved

1. **Started as**: a hosted platform to walk through an entire GitHub
   org's codebase, function by function, with AI explaining each one —
   competing with SonarQube/CodeScene (quality metrics) and a fast-moving
   cluster of "AI explains your repo" tools (DeepWiki, ExplainGitHub,
   Understand-Anything, GitSummarize).
2. **First correction**: that space is crowded and commoditizing fast.
   The real gap is narrower: **human-driven, AI-assisted** review that
   produces an audit trail — not AI replacing the reviewer, AI reducing
   the reviewer's reading burden while the human's decision is what
   gets recorded.
3. **Second correction**: mapped that idea onto actual regulatory
   language instead of a vague "code review is good" pitch. Existing
   GRC platforms (Vanta, Drata) evidence infrastructure and config well
   via API integrations, but structurally cannot evidence "a human
   reviewed this code" — that data doesn't exist until something
   produces it. Specific control mappings:
   - **ISO 27001:2022** Annex A 5.19–5.23 (supplier relationships / ICT
     supply chain), 8.25/8.26/8.28/8.29/8.32 (secure development
     lifecycle, secure coding, security testing, change management).
   - **DORA** Article 28–30: concentration risk, substitutability
     assessment, and exit strategy for critical ICT third parties —
     reviewed periodically, not just at onboarding.
4. **Scoped down for solo buildability**: the full platform (function-
   level review, IDE-style UI, drift-aware re-review, multi-tenant
   dashboard) is a company-sized effort. The **dependency ledger alone**
   is a weekend-to-weeks build for one person, reuses Syft (SBOM) and
   OSV (advisories) instead of building scanners from scratch, and maps
   onto the sharpest, most under-served piece of the control set
   (5.19–5.23).
5. **Corrected: per-repo vs. org-level scope**. Version/license/CVE
   checks are legitimately per-repo (different repos can run different
   versions). But "what is this dependency, why do we use it, what are
   the alternatives, how hard to replace it" is an organizational fact
   about the dependency — duplicating it across every repo that happens
   to use it is wasteful and invites inconsistency. Real precedent: a
   company's own internal dependency-documentation exercise didn't
   need per-repo entries — one JUnit5 entry served the whole org, built
   from what showed up across many repos' scans.
6. **Refined the approval model**: the org-level catalog needs sign-off
   from three distinct groups — engineering management, security, and
   legal — matching the three different kinds of judgment already
   implicit in the catalog's fields (feasibility/effort, risk,
   license/IP). Plain GitHub CODEOWNERS does *not* enforce this — an
   approval from any one listed team satisfies it. The correct
   mechanism is GitHub's newer ruleset-based "required review by
   specific teams," which can require one approval from *each* of
   several named teams.
7. **Added grandfathering**: turning a gate on for the first time
   against an existing org would block every existing service from
   shipping until every dependency clears full review — unworkable.
   Pre-existing dependencies get a `grandfathered` status, but it must
   never be permanent: a `catch_up_deadline` is required at creation.
   The org sets what that deadline actually is (a policy decision, not
   the tool's to dictate) — but the tool refuses to let grandfathering
   exist without one. A `materiality` tag (`business-critical` vs.
   `internal-tooling`) drives prioritization, separate from raw usage
   breadth: a dependency embedded in three production services matters
   more than one used in every repo's test harness, even though the
   latter has higher raw fan-out. Grandfathered items still escalate
   immediately, ahead of schedule, if a new CVE or version drift hits
   them before the deadline arrives — same "whichever comes first"
   logic as the calendar/drift re-review trigger below.

## Mechanisms worth remembering, since they get reused across scopes

- **Calendar OR drift, whichever comes first.** Re-review triggers off
  either a fixed cadence (annual/quarterly, like documentation review)
  or a change past some threshold (version drift, new CVE, usage/call-
  graph drift) — same pattern as a car service interval. Whichever
  fires first resets both clocks. This exact mechanism reappears for
  grandfathering deadlines and would reappear again for any future
  function-level review feature.
- **Chain-of-trust is about accountability, not omniscience.** No
  system can cryptographically prove a reviewer genuinely thought about
  the code — that's true of every real assurance framework, including
  SOC 2 auditor sign-off. What's achievable: bind a claim to a real
  identity (signed commits), make it tamper-evident (git history is
  already a hash chain), require a second party (branch protection /
  rulesets), and — if a real auditor ever asks for independent proof —
  layer Sigstore/Rekor on top, the same mechanism used for build
  provenance in SLSA/in-toto. The backstop against outright fabrication
  is the same as in every audit discipline: sampling, plus real
  consequence for the named signer, not a technical guarantee.
- **AI drafts, humans attest.** Anywhere AI analysis gets added (a
  future function-level review feature, or auto-suggesting which new
  SBOM entries belong to the same dependency family), it should surface
  questions or draft groupings for a human to confirm — never render a
  verdict that gets treated as the record.

## Market context (why this shape, not a bigger platform)

Bottom-up sizing landed on a few thousand realistic buyers globally —
companies holding ISO 27001/SOC 2 with real dependency surfaces, not
hundreds of thousands. That's not a venture-scale platform pitch, but
it's a real, provable niche, roughly the shape of smaller GRC
challengers (Sprinto, Secureframe) rather than Vanta/Drata themselves.
CodeRabbit is the nearest adjacent competitor technically (already
builds cross-file code graphs and PR-level walkthroughs) but is scoped
to merge velocity, not compliance evidence — that gap is real today but
not deeply defensible, so speed and a specific vertical foothold
(financial services / ISO 27001, leaning on prior hands-on experience
in that world) matter more than the idea itself.

**Deliberately not pursuing right now**: a Vanta/Drata distribution
partnership. Right resource-fit for a company, wrong one for a solo
builder with no BD capacity — revisit only after there's real usage.
