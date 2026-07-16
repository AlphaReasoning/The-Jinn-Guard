# Technical Appendix

## 1. Enforcement-plane analysis

### Kernel deterministic floor

Architecture and threat-model documentation consistently assert a non-cooperative kernel plane where LSM hooks make final map-backed verdicts:
- [SECURITY_ARCHITECTURE.md](../The-Jinn-Guard/SECURITY_ARCHITECTURE.md#L24)
- [SECURITY_ARCHITECTURE.md](../The-Jinn-Guard/SECURITY_ARCHITECTURE.md#L116)
- [SECURITY_ARCHITECTURE.md](../The-Jinn-Guard/SECURITY_ARCHITECTURE.md#L157)

Assessment:
- Strong for containment baseline.
- Important messaging caveat: this is deterministic policy-map enforcement, not semantic syscall gating.

### User-space governance path

Decision pipeline references include semantic scoring, invariants, and hard ceiling checks:
- [SECURITY_ARCHITECTURE.md](../The-Jinn-Guard/SECURITY_ARCHITECTURE.md#L144)
- [ts_cli/src/main.rs](../The-Jinn-Guard/ts_cli/src/main.rs#L2356)
- [ts_cli/src/main.rs](../The-Jinn-Guard/ts_cli/src/main.rs#L2398)

Assessment:
- Well-structured multi-gate chain.
- Requires careful claim wording to distinguish user-space assessment from kernel final syscall mediation.

## 2. Semantic governance analysis

Observed semantic service structures:
- [ts_cli/src/governance.rs](../The-Jinn-Guard/ts_cli/src/governance.rs#L218)
- [ts_cli/src/governance.rs](../The-Jinn-Guard/ts_cli/src/governance.rs#L294)
- [ts_cli/src/governance.rs](../The-Jinn-Guard/ts_cli/src/governance.rs#L408)

Assessment:
- Semantic analysis capability exists.
- Current public framing should be explicit that local heuristic classification is foundational, with optional external semantic enrichment.

## 3. Z3 assurance analysis

Evidence:
- [ts_checker/src/lib.rs](../The-Jinn-Guard/ts_checker/src/lib.rs#L42)
- [ts_checker/src/lib.rs](../The-Jinn-Guard/ts_checker/src/lib.rs#L77)
- [ts_checker/src/lib.rs](../The-Jinn-Guard/ts_checker/src/lib.rs#L99)
- [ts_checker/src/lib.rs](../The-Jinn-Guard/ts_checker/src/lib.rs#L16)

Assessment:
- Z3 is materially used and fail-closed behavior is documented and implemented.
- Strongest precise phrasing: "bounded SMT invariant and ceiling checks".
- Risky phrasing: broad "state transition proofs" unless formal proof obligations and semantics are explicitly defined and machine-checked beyond satisfiability checks.

## 4. Tamper-evident audit analysis

Evidence:
- [ts_cli/src/governance.rs](../The-Jinn-Guard/ts_cli/src/governance.rs#L1249)
- [ts_cli/src/governance.rs](../The-Jinn-Guard/ts_cli/src/governance.rs#L1685)
- [ts_cli/src/governance.rs](../The-Jinn-Guard/ts_cli/src/governance.rs#L2544)

Assessment:
- Strong implementation of append + chain verification mechanics.
- The ledger is the most compelling trust primitive for external reviewers.

## 5. Release integrity and provenance analysis

Evidence:
- [RELEASE_INTEGRITY.md](../The-Jinn-Guard/RELEASE_INTEGRITY.md#L1)
- [RELEASE_INTEGRITY.md](../The-Jinn-Guard/RELEASE_INTEGRITY.md#L49)
- [.github/workflows/release.yml](../The-Jinn-Guard/.github/workflows/release.yml#L83)
- [.github/workflows/release.yml](../The-Jinn-Guard/.github/workflows/release.yml#L106)

Assessment:
- Good release provenance posture with recognizable ecosystem standards.
- Current gap is stronger linkage between release-level provenance and per-action runtime attestations.

## 6. Residual risks (priority ordered)

1. Claim overreach risk in external narrative.
2. Semantic-layer interpretability and fallback transparency risk.
3. Runtime-to-external-attestation continuity gap.
4. Validation portability risk (environment/toolchain prerequisites).
