# Action Manifest v0 — per-action signed provenance (M9 / JG #62)

**Status: IMPLEMENTED (v0).** Shipped as `ts_cli/src/provenance_manifest.rs`
(signer + canonical serializer + Merkle checkpoints + verifier), wired into
`AuditLogger` and the `--manifest-key` / `--manifest-per-action` /
`--verify-manifests` CLI flags. 7 unit tests + end-to-end daemon validation.
This document is the original scoping; **as-built deviations** from it:

- **Signing is inline-after-commit, not a background thread.** It still runs only
  *after* the entry is on the chain (never on the decision path) and Ed25519 is
  ~tens of µs; a dedicated background signer/queue is deferred to v1. The "off the
  hot path" property holds; the "background" mechanism is simplified.
- **`kernel_enforced` claim is omitted in v0** (would overclaim — the `AuditEntry`
  carries no per-action kernel-enforcement flag yet). The v0 claim set is
  `verdict` / `denied_reason` / `intent_class` / `fused_risk` / `trust_score` /
  `z3_checked`, each mapped to a real committed field. Wiring `kernel_enforced` is
  a v1 item.
- **Single epoch (0).** Rotation epochs reuse the salt-epoch machinery in v1.
- **Canonical form** is the pinned sorted-key compact serializer with reference
  vectors (module tests); RFC 8785 JCS adoption is a forward-compatible v1 option.

Original scoping follows. Inline follow-up to the commissioned claim-calibration
review's C2PA readiness gap map (`docs/calibration-review-2026-06/C2PA_READINESS_GAP_MAP.md`).

This document scopes the one **net-new capability** the review identified: linking
the runtime decision ledger to a portable, externally-verifiable provenance format.
Everything else the audit flagged was claim wording and validation portability,
closed in PR #50.

---

## 1. The gap, stated precisely

The audit log today (`ts_cli/src/governance.rs`, `AuditEntry`) is a **SHA-256 hash
chain**: each entry commits to `index ‖ timestamp ‖ prev_hash ‖ observation ‖
intent ‖ assessment ‖ decision`, and `verify_chain()` re-walks the JSONL to confirm
every link (`ChainVerification`). PII is split into the erasable `audit_pii` store
(#61), so the chain survives crypto-shredding.

What this gives us: **tamper-evidence** — you cannot edit one entry in place without
breaking the chain.

What it does **not** give us: **authenticity / non-repudiation / external
verifiability**. The chain hash takes no secret, so anyone holding the JSONL can
recompute a *fully self-consistent* alternative chain. A third party handed a log
cannot prove it was produced by a genuine Jinn Guard instance, nor that it has not
been wholesale-regenerated. There is also no machine-readable claim taxonomy and no
portable verifier contract.

C2PA-style provenance closes exactly this: a **signed** assertion, bound to a signer
identity, with a stable schema a third party can verify offline.

## 2. Non-goals (v0)

- Not a blockchain; no consensus, no distributed ledger.
- Does **not** defend against a root attacker who holds the live signing key — that
  is a key-protection problem (see §7), the same trust boundary as the fleet key.
- Does **not** change any verdict. Provenance is emitted *after* a decision is
  committed; it never gates the hot path.
- Does not require network egress in the base profile (external anchoring is opt-in,
  Phase 2).

## 3. Design

### 3.1 Signing primitive — Ed25519 (asymmetric), not HMAC

Every existing signature in the tree is **HMAC-SHA256** (`ts_wire` envelope, fleet
bundles, audit per-record commitments). HMAC is symmetric: a verifier needs the
secret, so it cannot give *external* verifiability — the whole point here. v0
introduces an **Ed25519** runtime signer (`ed25519-dalek`, pure-Rust, no `ring`/
`aws-lc` — must be confirmed license-clean against `deny.toml` before adding; dalek
is BSD-3 and has cleared similar gates).

- The instance holds an Ed25519 **private key**; the **public key** is published
  (and optionally certified — §6).
- Verifiers need only the public key. This is the asymmetric property C2PA assumes.

### 3.2 What gets signed, and *off the hot path*

Two granularities, both emitted by a **background signer** so the verdict path
(P50 257 µs) is untouched:

1. **Per-action detached signature** (the C2PA "per-decision" target). After an
   `AuditEntry` is committed, the signer signs the entry's canonical bytes (the same
   bytes `calculate_hash` covers — so signatures and PII erasure stay compatible:
   the signature is over the redacted entry, never over `audit_pii`). Stored
   alongside the JSONL as `(index, sig, signer_key_id)`.
2. **Checkpoint signature** (efficiency + anchoring unit). Every *N* entries (or *T*
   seconds), sign a checkpoint = `{ last_index, merkle_root(entries since last
   checkpoint), prev_checkpoint_hash, signer_key_id, epoch }`. Checkpoints are the
   unit submitted to an external log in Phase 2, and let a verifier confirm a long
   log with O(checkpoints) signature checks instead of O(entries).

Ed25519 signing is ~20–50 µs; batched in the background it adds no decision latency.
v0 ships checkpoint signing as the default-on path and per-action signing as opt-in
(`JINNGUARD_MANIFEST_PER_ACTION=1`), because checkpoints give the same
non-repudiation at a fraction of the storage.

### 3.3 Manifest schema + canonical serialization

`ActionManifest` v0 (JSON, schema-versioned):

```jsonc
{
  "schema": "jinnguard/action-manifest@0",
  "index": 1234,
  "timestamp_secs": 1750000000,
  "prev_hash": "<hex>",
  "entry_hash": "<hex>",               // == AuditEntry.hash; the link to the chain
  "claims": {                          // machine-readable taxonomy — §3.4
    "kernel_enforced": true,
    "semantic_assessed": "heuristic",  // heuristic | external | both
    "z3_checked": "risk_ceiling+invariants",
    "verdict": "DENY",
    "denied_reason": "DENY_INTENT_NOT_ALLOWLISTED"
  },
  "signer_key_id": "<sha256(pubkey)[..16]>",
  "epoch": 3
}
```

Canonicalization: a **documented canonical form** (sorted keys, no insignificant
whitespace — RFC 8785 JCS, or our own pinned serializer) with **published reference
vectors** so any language can reproduce the exact signed bytes. This is the piece
the audit explicitly asked for ("publish verifier CLI output format and canonical
reference vectors").

### 3.4 Claim taxonomy

Maps existing decision state onto the four classes the gap map named, derived
deterministically from the `AuditEntry`:

| Claim | Source field | Meaning |
|---|---|---|
| `kernel_enforced` | whether the action fell in the governed cgroup scope + a kernel hook applied | the deterministic floor acted (not just user-space) |
| `semantic_assessed` | `intent` / `assessment` provenance | heuristic-only vs external scorer vs both |
| `z3_checked` | `assessment` (ceiling + invariants run) | which bounded SMT checks ran |
| `verdict` / `denied_reason` | `decision` | outcome + the specific `DENY_*` reason code |

This is the same honesty split as README's Guarantees table, but machine-readable
per action — a downstream system can filter "show me actions the *kernel floor*
actually enforced" vs "user-space assessed only."

### 3.5 Verifier CLI

`ts_cli verify-manifests <audit_dir>` (and a library entrypoint), reporting:

1. **Chain integrity** — reuse `verify_chain()`.
2. **Authenticity** — every per-action sig / checkpoint sig verifies against the
   published signer pubkey(s) for its epoch; `entry_hash` in each manifest matches
   the chain entry.
3. **Coverage** — no committed entry lacks a covering signature (per-action or
   enclosing checkpoint); report gaps explicitly (no silent partial coverage).
4. **(Phase 2)** external inclusion — checkpoint present in the transparency log.

Ships with canonical reference vectors (a tiny fixture log + expected manifests +
expected verifier output) so external reviewers verify the verifier.

## 4. Phasing

- **v0 (this task):** Ed25519 runtime key + key-id; background checkpoint signing
  (per-action opt-in); `ActionManifest` schema + canonical serializer + reference
  vectors; `verify-manifests` CLI doing chain + authenticity + coverage; claim
  taxonomy; docs (THREAT_MODEL + SECURITY_ARCHITECTURE + Guarantees table row flips
  from 🚧 to ✅). **No network.**
- **v1:** Merkle proofs for single-entry inclusion without the whole log; key
  rotation epochs (reuse the salt-rotation epoch machinery already in
  `governance.rs`).
- **v2 (optional, network):** external transparency anchoring — submit checkpoint
  hashes to Sigstore **Rekor** (or a self-hosted append-only log); verifier checks
  inclusion proofs. Bind the runtime pubkey to the **release** identity by signing
  the pubkey with the cosign keyless flow at release time, closing the
  runtime↔release provenance loop the audit's appendix §5 wanted.

## 5. Privacy / GDPR interaction (#61)

Signatures cover the **redacted** entry bytes (exactly what `calculate_hash`
covers), never `audit_pii`. Crypto-shredding deletes only `audit_pii` rows, so
erasing a subject's PII leaves every signature and the chain valid — provenance and
the right-to-erasure stay compatible. State this explicitly in THREAT_MODEL.

## 6. Key management & identity

- Runtime Ed25519 private key stored root-only like the fleet key
  (`/etc/jinnguard/manifest.key`, 0600), generated on first start if absent;
  `signer_key_id = sha256(pubkey)[..16]`.
- Pubkey published in the repo / release assets; rotation via epochs (entries carry
  `epoch`; verifier maps epoch → pubkey).
- v2: cosign-sign the pubkey at release so a verifier can chain
  *action → runtime key → release identity (OIDC)*.

## 7. Threat model delta (what it adds / doesn't)

- **Adds:** non-repudiation and offline external verifiability — a third party with
  only the pubkey can confirm a log was produced by a genuine instance and not
  wholesale-forged or regenerated.
- **Does not add:** protection against an attacker who already holds the live
  signing key (root on the host). That is the existing root-trust boundary; mitigate
  with key file permissions, optional TPM/HSM-backed keys (future), and external
  anchoring (v2) which at least makes *silent* retroactive forgery detectable
  (a forked log cannot match the public transparency log).

## 8. Acceptance criteria

- [ ] `ActionManifest` schema + canonical serializer with published reference vectors.
- [ ] Background checkpoint signer; verdict-path latency unchanged (bench delta within noise).
- [ ] `verify-manifests` CLI: chain + authenticity + coverage; non-zero exit on any gap or bad sig.
- [ ] Tamper test: flip one entry → chain breaks AND signature fails (two independent detections).
- [ ] Forgery test: regenerate a self-consistent chain with a *different* key → chain "intact" but authenticity FAILS (proves the gap is closed).
- [ ] Erasure test: crypto-shred a subject → signatures + chain still verify.
- [ ] `cargo-deny` green with `ed25519-dalek` added (licenses/bans/advisories).
- [ ] Docs updated; README Guarantees-table rows for manifests/anchoring flip 🚧→✅ as phases land.

## 9. Estimated shape

- v0 is ~1 focused module (`provenance_manifest.rs`) + CLI subcommand + verifier +
  reference vectors + docs. No VMs, no kernel matrix (pure user-space crypto +
  SQLite/JSONL); validates in normal CI (`cargo test -p ts_cli`).
- v2 is the only part needing network and a transparency-log dependency; gate it
  behind a feature flag so the base build stays egress-free.
