# Claim-Evidence Matrix

## Method

Each claim is labeled as:
- Validated: implementation and docs are aligned.
- Partially supported: implementation exists but wording overreaches.
- Overstated: current wording materially exceeds wired behavior.

## Matrix

| Claim | Status | Evidence | Notes |
|---|---|---|---|
| Kernel-level governance enforces allow/deny at syscall plane | Validated | [SECURITY_ARCHITECTURE.md](../The-Jinn-Guard/SECURITY_ARCHITECTURE.md#L157), [SECURITY_ARCHITECTURE.md](../The-Jinn-Guard/SECURITY_ARCHITECTURE.md#L159) | Kernel plane is independent of user-space liveness. |
| Semantic decision path exists in daemon | Validated | [ts_cli/src/governance.rs](../The-Jinn-Guard/ts_cli/src/governance.rs#L218), [ts_cli/src/governance.rs](../The-Jinn-Guard/ts_cli/src/governance.rs#L294) | Local heuristic + optional combined service are implemented. |
| Semantic scoring is primarily NLP understanding | Partially supported | [README.md](../The-Jinn-Guard/README.md#L5), [ts_cli/src/governance.rs](../The-Jinn-Guard/ts_cli/src/governance.rs#L218) | Primary mode is heuristic intent/risk classification; external scorer is optional. |
| Z3 checks are in the runtime path | Validated | [ts_cli/src/main.rs](../The-Jinn-Guard/ts_cli/src/main.rs#L2356), [ts_cli/src/main.rs](../The-Jinn-Guard/ts_cli/src/main.rs#L2658) | Invariant verification and risk ceiling integration are wired. |
| Z3 provides formal state-transition proofs | Overstated | [README.md](../The-Jinn-Guard/README.md#L202), [ts_checker/src/lib.rs](../The-Jinn-Guard/ts_checker/src/lib.rs#L77) | Current core shown is bounded arithmetic/invariant satisfiability checks. |
| Z3 fails closed on solver uncertainty/timeouts | Validated | [ts_checker/src/lib.rs](../The-Jinn-Guard/ts_checker/src/lib.rs#L16), [SECURITY_ARCHITECTURE.md](../The-Jinn-Guard/SECURITY_ARCHITECTURE.md#L151) | Explicitly documented and implemented as deny on unknown. |
| Audit log is tamper-evident hash-chained | Validated | [ts_cli/src/governance.rs](../The-Jinn-Guard/ts_cli/src/governance.rs#L1249), [ts_cli/src/governance.rs](../The-Jinn-Guard/ts_cli/src/governance.rs#L1685) | Chain hash creation + verification path exists. |
| Audit chain has corruption detection tests | Validated | [ts_cli/src/governance.rs](../The-Jinn-Guard/ts_cli/src/governance.rs#L2544), [ts_cli/src/governance.rs](../The-Jinn-Guard/ts_cli/src/governance.rs#L2617) | Test section includes verification assertions. |
| Release artifacts have provenance and signatures | Validated | [RELEASE_INTEGRITY.md](../The-Jinn-Guard/RELEASE_INTEGRITY.md#L14), [.github/workflows/release.yml](../The-Jinn-Guard/.github/workflows/release.yml#L83), [.github/workflows/release.yml](../The-Jinn-Guard/.github/workflows/release.yml#L106) | SLSA provenance and cosign keyless are explicitly wired. |
| Full validation harness is one-command reproducible | Partially supported | [scripts/run_professor_validation.sh](../The-Jinn-Guard/scripts/run_professor_validation.sh#L3), [scripts/run_professor_validation.sh](../The-Jinn-Guard/scripts/run_professor_validation.sh#L31) | Requires Rust toolchain/root for full tiers; macOS bash compatibility issue observed in this run. |
