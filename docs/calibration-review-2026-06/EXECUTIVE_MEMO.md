# Executive Memo: The-Jinn-Guard Analysis

Date: 2026-06-29

## Bottom line

The repository demonstrates a serious and non-trivial governance architecture with three defensible strengths:
1. Kernel-level, cgroup-scoped enforcement via eBPF-LSM hooks.
2. Tamper-evident hash-chained audit logging with explicit verification support.
3. Release provenance posture using SLSA v3 + cosign keyless signatures.

The main concern is claim calibration, not absence of engineering. Some published language still overstates what is currently wired:
- Z3 use is real but bounded and satisfiability-oriented.
- Semantic decisioning is primarily heuristic with optional external scoring.
- Kernel enforcement is deterministic and map-driven, not semantically gated by user-space decisions.

## What is strongly defensible now

1. Kernel floor exists independent of daemon cooperation:
   - [SECURITY_ARCHITECTURE.md](../The-Jinn-Guard/SECURITY_ARCHITECTURE.md#L157)
   - [SECURITY_ARCHITECTURE.md](../The-Jinn-Guard/SECURITY_ARCHITECTURE.md#L159)
2. Audit chain is tamper-evident and verifiable:
   - [ts_cli/src/governance.rs](../The-Jinn-Guard/ts_cli/src/governance.rs#L1249)
   - [ts_cli/src/governance.rs](../The-Jinn-Guard/ts_cli/src/governance.rs#L1685)
3. Supply-chain attestation is present in release flow:
   - [RELEASE_INTEGRITY.md](../The-Jinn-Guard/RELEASE_INTEGRITY.md#L14)
   - [.github/workflows/release.yml](../The-Jinn-Guard/.github/workflows/release.yml#L83)

## Highest-priority claim risks

1. "State transition proofs" wording likely overstates current Z3 model scope.
   - [README.md](../The-Jinn-Guard/README.md#L5)
   - [ts_checker/src/lib.rs](../The-Jinn-Guard/ts_checker/src/lib.rs#L77)
2. "Semantic firewall" phrasing should explicitly disclose heuristic primary mode.
   - [README.md](../The-Jinn-Guard/README.md#L5)
   - [ts_cli/src/governance.rs](../The-Jinn-Guard/ts_cli/src/governance.rs#L218)
3. User-space semantic verdict should not be interpreted as kernel syscall gate today.
   - [SECURITY_ARCHITECTURE.md](../The-Jinn-Guard/SECURITY_ARCHITECTURE.md#L157)
   - [SECURITY_ARCHITECTURE.md](../The-Jinn-Guard/SECURITY_ARCHITECTURE.md#L159)

## Recommendation snapshot

1. Keep current architecture claims, but split them by plane: kernel deterministic floor vs user-space semantic/risk gate.
2. Replace "proof" language with "bounded SMT invariant checks" unless quantified proof obligations are implemented.
3. Lead external messaging with strongest validated asset: tamper-evident action ledger + release provenance chain.
4. Publish a transparent "current guarantees vs roadmap" table in README.
