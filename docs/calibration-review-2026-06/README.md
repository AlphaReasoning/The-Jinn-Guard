# Claim-calibration review — June 2026

This folder publishes, verbatim, the artifacts of a **commissioned claim-calibration
review** of Jinn Guard carried out in June 2026 (dated 2026-06-28/29).

**This was NOT a third-party security audit.** It was an external claim-calibration
review: an outside reader checked whether the repository's published language matched
what the code actually does, and scored governance maturity. It did not perform
penetration testing, exploit development, or a formal security assessment. The
standing "no independent third-party security audit yet" item remains open — see
[`RESIDUAL_RISKS.md`](../../RESIDUAL_RISKS.md) **RR-001**, which is authoritative.

The unflattering entries (the "Overstated" labels in the claim-evidence matrix, the
maturity scores) are kept **exactly as written**. They are the point of publishing
this: the review's value is that it was critical, and the record shows which criticisms
were acted on.

## Contents (verbatim, unedited)

| File | What it is |
|---|---|
| [`EXECUTIVE_MEMO.md`](EXECUTIVE_MEMO.md) | Bottom-line findings: strengths, the claim-calibration concern, highest-priority claim risks, recommendation snapshot. |
| [`CLAIM_EVIDENCE_MATRIX.md`](CLAIM_EVIDENCE_MATRIX.md) | Per-claim adjudication (Supported / Overstated / …) with code-anchor evidence. |
| [`GOVERNANCE_MATURITY_SCORECARD.md`](GOVERNANCE_MATURITY_SCORECARD.md) | Governance maturity scoring. |
| [`C2PA_READINESS_GAP_MAP.md`](C2PA_READINESS_GAP_MAP.md) | Maps evidence primitives to C2PA-style action-provenance expectations; lists the gaps to close. |
| [`TECHNICAL_APPENDIX.md`](TECHNICAL_APPENDIX.md) | Supporting technical detail and evidence anchors. |
| [`VALIDATION_STATUS.md`](VALIDATION_STATUS.md) | What the reviewer actually executed (portable-crate tests, harden of the validation harness) and the environment-gated skips. |

> Note: internal cross-links inside these artifacts point at repository files using
> the reviewer's original relative paths (e.g. `../The-Jinn-Guard/...`), preserved
> unedited. Read them against the repository root.

## Gap → closure trail

Each gap the review identified, mapped to the commit/PR that closed it. Real commit
hashes only; items with no closing commit are marked **Open** rather than assigned an
invented one.

| # | Gap identified by the review | Status | Closing commit / PR (or roadmap) |
|---|---|---|---|
| 1 | "State-transition proof" / proof wording overstates the bounded Z3 model | **Closed** | Claim calibration `9ff64f1` (PR #50 `1b0b22b`); claim-hygiene `cff00da`; residual "provably" sweep `6a9c8ea` (this branch) |
| 2 | "Semantic firewall" phrasing should disclose heuristic-primary mode | **Closed** | `9ff64f1` (PR #50 `1b0b22b`) — README `ts_checker`/semantic rows recalibrated |
| 3 | User-space semantic verdict must not read as a kernel syscall gate | **Closed** | Plane-split "guarantees today — vs roadmap" table added in `9ff64f1`; un-staled in `134dc68` (PR #60 `0696529`) |
| 4 | Publish a transparent "current guarantees vs roadmap" table | **Closed** | `9ff64f1`; kept current by `134dc68` (PR #60 `0696529`) |
| 5 | C2PA gap: decision-level signed action manifests | **Closed** | Action Manifest v0 `94be991` (PR #52 `f9c889b`); verifier-key pinning `c2af362` |
| 6 | C2PA gap: portable verifier output format + canonical reference vectors | **Closed** | Canonical serializer + reference-vector module tests shipped with Action Manifest v0 `94be991` |
| 7 | C2PA gap: external transparency-log anchoring of action-chain checkpoints | **Open** | Roadmap (README guarantees table: "External transparency-log anchoring — Roadmap, JG #62 v2"); no closing commit |
| 8 | C2PA gap: hardware-/platform-backed signer identity for runtime actions | **Open** | Roadmap; no closing commit |
| 9 | C2PA gap: explicit machine-readable claim taxonomy (kernel_enforced / semantic_assessed / z3_checked / denied_reason) | **Open** (partially addressed) | Action Manifest v0 `94be991` records per-decision verdict/reason fields, but the full standardized claim taxonomy is not yet implemented; no dedicated closing commit |

_Review dated 2026-06-28/29. Artifacts copied into the tree 2026-07-15 for
launch transparency; contents unmodified from the originals._
