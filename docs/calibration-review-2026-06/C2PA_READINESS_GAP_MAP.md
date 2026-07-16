# C2PA-Style Readiness and Gap Map

## Objective

Map current Jinn Guard evidence primitives to C2PA-style provenance expectations for "agent action provenance".

## Mapping

| C2PA-like concept | Current implementation | Evidence | Readiness |
|---|---|---|---|
| Claim record immutability | Hash-chained audit entries with prev-hash linkage | [ts_cli/src/governance.rs](../The-Jinn-Guard/ts_cli/src/governance.rs#L1249), [ts_cli/src/governance.rs](../The-Jinn-Guard/ts_cli/src/governance.rs#L1685) | High |
| Claim generation context | Decision pipeline includes intent, risk, invariant checks, and verdict | [SECURITY_ARCHITECTURE.md](../The-Jinn-Guard/SECURITY_ARCHITECTURE.md#L144), [ts_cli/src/main.rs](../The-Jinn-Guard/ts_cli/src/main.rs#L2356) | Medium-High |
| Signing identity / trust anchor for build artifacts | OIDC-bound cosign keyless + SLSA provenance | [RELEASE_INTEGRITY.md](../The-Jinn-Guard/RELEASE_INTEGRITY.md#L28), [.github/workflows/release.yml](../The-Jinn-Guard/.github/workflows/release.yml#L83) | High (release) |
| Runtime chain verification | In-repo verify function and tests | [ts_cli/src/governance.rs](../The-Jinn-Guard/ts_cli/src/governance.rs#L1685), [ts_cli/src/governance.rs](../The-Jinn-Guard/ts_cli/src/governance.rs#L2544) | High |
| Non-cooperative enforcement provenance | Kernel plane independent of daemon cooperation | [SECURITY_ARCHITECTURE.md](../The-Jinn-Guard/SECURITY_ARCHITECTURE.md#L157) | Medium-High |
| Cross-system externally verifiable action manifests | Not yet a standardized C2PA manifest envelope for each action decision | Current repo state | Gap |

## Key gaps to close for C2PA-like interoperability

1. Decision-level signed manifests:
   - Add per-decision signed claim envelopes (detached or embedded) with stable schema.
2. External transparency anchoring:
   - Anchor action-chain checkpoints to external transparency logs.
3. Stronger signer identity model for runtime actions:
   - Bind runtime signer identity to hardware-/platform-backed keys where possible.
4. Explicit claim taxonomy:
   - Define machine-readable claim classes: kernel_enforced, semantic_assessed, z3_checked, denied_reason.
5. Portable verifier package:
   - Publish verifier CLI output format and canonical reference vectors.

## Practical next phase

1. Introduce Action Manifest v0 (JSON schema + canonical serialization).
2. Sign each manifest with runtime key and include previous-manifest hash.
3. Publish a verifier that checks both local chain integrity and external checkpoint inclusion.
