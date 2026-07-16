# Governance Maturity Scorecard

Scale: 1 (early) to 5 (advanced). Scores reflect current evidence in-repo and executed validation constraints in this environment.

| Pillar | Score | Confidence | Basis |
|---|---:|---|---|
| Kernel mediation robustness | 4.0 | Medium-High | Clear architecture and test scaffolding for LSM enforcement. See [SECURITY_ARCHITECTURE.md](../The-Jinn-Guard/SECURITY_ARCHITECTURE.md#L91), [SECURITY_ARCHITECTURE.md](../The-Jinn-Guard/SECURITY_ARCHITECTURE.md#L157). |
| Semantic governance rigor | 3.0 | Medium | Implemented and layered, but claim precision should reflect heuristic-primary mode. See [ts_cli/src/governance.rs](../The-Jinn-Guard/ts_cli/src/governance.rs#L218), [README.md](../The-Jinn-Guard/README.md#L5). |
| Formal methods rigor (Z3) | 3.0 | Medium | Real SMT checks with fail-closed timeout, but broad "proof" language should be narrowed to bounded invariants/ceilings. See [ts_checker/src/lib.rs](../The-Jinn-Guard/ts_checker/src/lib.rs#L77), [ts_checker/src/lib.rs](../The-Jinn-Guard/ts_checker/src/lib.rs#L16). |
| Audit ledger integrity | 4.5 | High | Strong hash-chain and verification mechanics with tests. See [ts_cli/src/governance.rs](../The-Jinn-Guard/ts_cli/src/governance.rs#L1249), [ts_cli/src/governance.rs](../The-Jinn-Guard/ts_cli/src/governance.rs#L1685). |
| Release attestation chain | 4.0 | High | SLSA + cosign keyless integrated. See [.github/workflows/release.yml](../The-Jinn-Guard/.github/workflows/release.yml#L83), [RELEASE_INTEGRITY.md](../The-Jinn-Guard/RELEASE_INTEGRITY.md#L49). |
| Operational validation readiness | 2.5 | Medium | Rich validation script exists, but local execution currently blocked by toolchain/shell/runtime prerequisites. See [VALIDATION_STATUS.md](./VALIDATION_STATUS.md). |

## Overall

Composite maturity: 3.5 / 5.0

Interpretation:
- Technically substantial PoC with strong primitives.
- Main path to higher maturity is claim calibration plus cross-environment reproducible validation and runtime attestation continuity.
