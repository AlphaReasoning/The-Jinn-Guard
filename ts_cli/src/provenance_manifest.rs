//! Per-action signed provenance manifests — **Action Manifest v0** (JG #62 / M9).
//!
//! ## What this adds, precisely
//!
//! The audit ledger (`governance::AuditLogger`) is a SHA-256 hash chain: it gives
//! **tamper-evidence** (you cannot edit one entry in place without breaking the
//! chain). It does *not* give **authenticity** — the chain hash takes no secret,
//! so anyone holding the JSONL can recompute a fully self-consistent alternative
//! chain. A third party cannot prove a log was produced by a genuine Jinn Guard
//! instance, nor that it was not wholesale-regenerated.
//!
//! This module closes exactly that gap with an **Ed25519** (asymmetric) signature
//! over a stable, machine-readable manifest. Verifiers need only the *public* key
//! — the property HMAC (symmetric, used everywhere else in the tree) cannot give.
//!
//! ## What it does NOT add
//!
//! - It does not change any verdict. Manifests are emitted *after* a decision is
//!   committed to the chain; they never gate the decision hot path.
//! - It does not defend against an attacker who already holds the live signing key
//!   (root on the host). That is the existing root-trust boundary. External
//!   transparency anchoring (a v2 item) is what makes *silent* retroactive forgery
//!   detectable; v0 is offline non-repudiation only.
//!
//! ## Granularity
//!
//! Two signed units, both off the decision path:
//!
//! * **Checkpoint** (default). Every `interval` committed entries, sign a
//!   checkpoint binding a Merkle root over the entry hashes in the range. One
//!   signature authenticates a whole range — O(checkpoints) verifications for a
//!   long log instead of O(entries).
//! * **Per-action manifest** (opt-in, `JINNGUARD_MANIFEST_PER_ACTION=1`). One
//!   detached signature per `AuditEntry`, carrying the machine-readable claim
//!   taxonomy. Heavier on storage; use when downstream systems consume per-action
//!   provenance directly.
//!
//! ## Privacy (#61)
//!
//! Signatures cover the **redacted** entry bytes — exactly what
//! [`governance::AuditEntry::calculate_hash`] covers — never `audit_pii`.
//! Crypto-shredding deletes only `audit_pii`; every signature and the chain stay
//! valid after erasure. Provenance and the right-to-erasure are compatible.

use anyhow::{anyhow, Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use std::path::Path;
use std::sync::Mutex;

use crate::governance::{AuditEntry, PolicyVerdict};

/// Schema id stamped into every action manifest.
pub const ACTION_SCHEMA: &str = "jinnguard/action-manifest@0";
/// Schema id stamped into every checkpoint.
pub const CHECKPOINT_SCHEMA: &str = "jinnguard/manifest-checkpoint@0";
/// Default entries-per-checkpoint when `JINNGUARD_MANIFEST_CHECKPOINT_INTERVAL`
/// is unset. Small enough that a crash loses at most this many entries' coverage
/// (recoverable by re-running with `--verify-manifests` after a flush).
pub const DEFAULT_CHECKPOINT_INTERVAL: u64 = 64;

const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

// ---------------------------------------------------------------------------
// Canonical serialization
// ---------------------------------------------------------------------------

/// Deterministic JSON: object keys sorted recursively, compact (no insignificant
/// whitespace). This is the byte sequence that gets signed and re-derived by any
/// verifier. Pinned here with published reference vectors (see the module tests)
/// so the signed bytes are reproducible; a future revision may adopt RFC 8785 JCS
/// wholesale, but the contract is "these exact bytes for this value".
pub fn canonical_json(value: &serde_json::Value) -> String {
    let mut out = String::new();
    write_canonical(value, &mut out);
    out
}

fn write_canonical(value: &serde_json::Value, out: &mut String) {
    match value {
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                // serde_json::to_string on a string yields a correctly-escaped
                // JSON string literal; reuse it for keys and leaf strings.
                out.push_str(&serde_json::to_string(k).unwrap_or_default());
                out.push(':');
                write_canonical(&map[*k], out);
            }
            out.push('}');
        }
        serde_json::Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        // Scalars: serde_json already emits a canonical, compact form (ryu for
        // floats — shortest round-trip; integers exact; booleans/null literal).
        other => out.push_str(&serde_json::to_string(other).unwrap_or_default()),
    }
}

fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let v = serde_json::to_value(value).context("manifest -> json value")?;
    Ok(canonical_json(&v).into_bytes())
}

// ---------------------------------------------------------------------------
// Claim taxonomy
// ---------------------------------------------------------------------------

/// Machine-readable claims derived **deterministically** from an `AuditEntry`.
///
/// Every field maps to a real field already present in the committed entry — no
/// claim is invented. `kernel_enforced` is deliberately *absent* in v0: the
/// `AuditEntry` does not yet carry a per-action kernel-enforcement flag, so
/// asserting it here would overclaim. Wiring that through is a v1 item (it
/// requires the decision path to record whether a kernel LSM hook actually fired
/// for the action, not just that the agent was in governed scope).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ManifestClaims {
    /// `Allow` | `Constrain` | `Deny`.
    pub verdict: String,
    /// The `DENY_*` / human reason, present only when the verdict denied.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub denied_reason: Option<String>,
    /// Coarse intent class the semantic layer assigned.
    pub intent_class: String,
    /// Fused risk score the assessment produced (0–100).
    pub fused_risk: f64,
    /// Trust score (100 − fused_risk).
    pub trust_score: f64,
    /// Which bounded SMT checks the policy engine runs for every decision. A
    /// static capability marker, not a per-action proof — the engine always runs
    /// the risk-ceiling inequality and declarative-invariant satisfiability.
    pub z3_checked: String,
}

impl ManifestClaims {
    pub fn from_entry(entry: &AuditEntry) -> Self {
        let denied_reason = match entry.decision.verdict {
            PolicyVerdict::Deny => Some(entry.decision.reason.clone()),
            _ => None,
        };
        Self {
            verdict: format!("{:?}", entry.decision.verdict),
            denied_reason,
            intent_class: format!("{:?}", entry.intent.class),
            fused_risk: entry.assessment.fused_risk,
            trust_score: entry.assessment.trust_score,
            z3_checked: "risk_ceiling+invariants".to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// Manifest + checkpoint records
// ---------------------------------------------------------------------------

/// One signed per-action provenance manifest. `entry_hash` is the link back to
/// the chain — a verifier confirms it equals `AuditEntry.hash` at `index`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ActionManifest {
    pub schema: String,
    pub index: u64,
    pub timestamp_secs: u64,
    pub prev_hash: String,
    pub entry_hash: String,
    pub claims: ManifestClaims,
    pub signer_key_id: String,
    pub epoch: u64,
}

impl ActionManifest {
    fn from_entry(entry: &AuditEntry, signer_key_id: &str, epoch: u64) -> Self {
        Self {
            schema: ACTION_SCHEMA.to_string(),
            index: entry.index,
            timestamp_secs: entry.timestamp_secs,
            prev_hash: entry.prev_hash.clone(),
            entry_hash: entry.hash.clone(),
            claims: ManifestClaims::from_entry(entry),
            signer_key_id: signer_key_id.to_string(),
            epoch,
        }
    }
}

/// A signed checkpoint over the entry-hash range `[first_index, last_index]`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Checkpoint {
    pub schema: String,
    pub first_index: u64,
    pub last_index: u64,
    /// Merkle root over the entry hashes in the range (see [`merkle_root`]).
    pub merkle_root: String,
    /// SHA-256 over the canonical bytes of the previous checkpoint (`ZERO_HASH`
    /// for the first), chaining checkpoints so one cannot be dropped silently.
    pub prev_checkpoint_hash: String,
    pub signer_key_id: String,
    pub epoch: u64,
}

/// On-disk manifest record (one per line in `<audit>.manifests`). The signature
/// covers the canonical bytes of the inner `manifest` / `checkpoint` only.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ManifestRecord {
    Action {
        manifest: ActionManifest,
        sig: String,
    },
    Checkpoint {
        checkpoint: Checkpoint,
        sig: String,
    },
}

/// Binary Merkle root over an ordered list of entry-hash hex strings.
///
/// * empty list  → `ZERO_HASH`
/// * leaf        → `SHA256("leaf:" ‖ hash_hex)`
/// * node        → `SHA256("node:" ‖ left ‖ right)`
/// * odd level   → the last node is promoted unchanged
///
/// Domain-separated leaf/node prefixes prevent second-preimage games between a
/// leaf and an internal node.
pub fn merkle_root(entry_hashes: &[String]) -> String {
    if entry_hashes.is_empty() {
        return ZERO_HASH.to_string();
    }
    let mut level: Vec<String> = entry_hashes
        .iter()
        .map(|h| {
            let mut hasher = Sha256::new();
            hasher.update(b"leaf:");
            hasher.update(h.as_bytes());
            hex::encode(hasher.finalize())
        })
        .collect();

    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            if i + 1 < level.len() {
                let mut hasher = Sha256::new();
                hasher.update(b"node:");
                hasher.update(level[i].as_bytes());
                hasher.update(level[i + 1].as_bytes());
                next.push(hex::encode(hasher.finalize()));
                i += 2;
            } else {
                next.push(level[i].clone());
                i += 1;
            }
        }
        level = next;
    }
    level.pop().unwrap_or_else(|| ZERO_HASH.to_string())
}

fn checkpoint_hash(cp: &Checkpoint) -> Result<String> {
    let bytes = canonical_bytes(cp)?;
    Ok(hex::encode(Sha256::digest(&bytes)))
}

/// `signer_key_id = first 16 bytes of SHA-256(pubkey), hex` (32 hex chars).
pub fn key_id_from_pubkey(vk: &VerifyingKey) -> String {
    let digest = Sha256::digest(vk.to_bytes());
    hex::encode(&digest[..16])
}

// ---------------------------------------------------------------------------
// Signer
// ---------------------------------------------------------------------------

struct CheckpointState {
    /// Entry hashes accumulated since the last emitted checkpoint.
    pending: Vec<String>,
    first_index: Option<u64>,
    prev_checkpoint_hash: String,
}

/// Holds the runtime Ed25519 key and appends signed manifests/checkpoints to
/// `<audit>.manifests`. Cheap (Ed25519 sign ≈ tens of µs) and only invoked after
/// an entry is already committed to the chain, so it is off the decision path.
pub struct ManifestSigner {
    signing_key: SigningKey,
    key_id: String,
    epoch: u64,
    per_action: bool,
    checkpoint_interval: u64,
    manifests_path: String,
    state: Mutex<CheckpointState>,
}

impl ManifestSigner {
    /// Load the runtime key from `key_path` (32-byte seed, lowercase hex) or
    /// generate one on first use and persist it `0600`. Publishes the public key
    /// next to the manifests file as `<manifests_path>.pub` (hex) so a verifier
    /// can be handed the directory and check it offline.
    pub fn load_or_generate(
        key_path: &str,
        audit_log_path: &str,
        per_action: bool,
        epoch: u64,
        checkpoint_interval: u64,
    ) -> Result<Self> {
        let seed = load_or_create_seed(key_path)?;
        let signing_key = SigningKey::from_bytes(&seed);
        let vk = signing_key.verifying_key();
        let key_id = key_id_from_pubkey(&vk);

        let manifests_path = format!("{audit_log_path}.manifests");
        let pubkey_path = format!("{manifests_path}.pub");
        // Publish the pubkey (hex). Idempotent: a rotation overwrites it, and the
        // epoch carried in each record tells a verifier which key applied.
        fs::write(&pubkey_path, hex::encode(vk.to_bytes()))
            .with_context(|| format!("publishing manifest pubkey to {pubkey_path}"))?;

        let interval = if checkpoint_interval == 0 {
            DEFAULT_CHECKPOINT_INTERVAL
        } else {
            checkpoint_interval
        };

        Ok(Self {
            signing_key,
            key_id,
            epoch,
            per_action,
            checkpoint_interval: interval,
            manifests_path,
            state: Mutex::new(CheckpointState {
                pending: Vec::new(),
                first_index: None,
                prev_checkpoint_hash: ZERO_HASH.to_string(),
            }),
        })
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(self.signing_key.verifying_key().to_bytes())
    }

    fn sign_hex(&self, bytes: &[u8]) -> String {
        let sig: Signature = self.signing_key.sign(bytes);
        hex::encode(sig.to_bytes())
    }

    fn append_record(&self, record: &ManifestRecord) -> Result<()> {
        use std::io::Write;
        let line = serde_json::to_string(record)? + "\n";
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.manifests_path)
            .with_context(|| format!("opening manifests file {}", self.manifests_path))?;
        file.write_all(line.as_bytes())?;
        Ok(())
    }

    /// Record provenance for one freshly-committed entry. Appends a per-action
    /// manifest when in per-action mode, and rolls a checkpoint when the pending
    /// batch reaches `checkpoint_interval`. Never blocks the caller's decision —
    /// the entry is already on the chain before this runs.
    pub fn record_entry(&self, entry: &AuditEntry) -> Result<()> {
        if self.per_action {
            let manifest = ActionManifest::from_entry(entry, &self.key_id, self.epoch);
            let sig = self.sign_hex(&canonical_bytes(&manifest)?);
            self.append_record(&ManifestRecord::Action { manifest, sig })?;
        }

        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow!("manifest signer state poisoned"))?;
        if state.first_index.is_none() {
            state.first_index = Some(entry.index);
        }
        state.pending.push(entry.hash.clone());

        if state.pending.len() as u64 >= self.checkpoint_interval {
            self.emit_checkpoint_locked(&mut state)?;
        }
        Ok(())
    }

    /// Force-sign a checkpoint over any pending entries (call on a clean shutdown
    /// or before verifying, so the trailing partial batch is covered).
    pub fn flush(&self) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow!("manifest signer state poisoned"))?;
        if !state.pending.is_empty() {
            self.emit_checkpoint_locked(&mut state)?;
        }
        Ok(())
    }

    fn emit_checkpoint_locked(&self, state: &mut CheckpointState) -> Result<()> {
        let first_index = state.first_index.unwrap_or(0);
        let last_index = first_index + state.pending.len() as u64 - 1;
        let checkpoint = Checkpoint {
            schema: CHECKPOINT_SCHEMA.to_string(),
            first_index,
            last_index,
            merkle_root: merkle_root(&state.pending),
            prev_checkpoint_hash: state.prev_checkpoint_hash.clone(),
            signer_key_id: self.key_id.clone(),
            epoch: self.epoch,
        };
        let sig = self.sign_hex(&canonical_bytes(&checkpoint)?);
        let this_hash = checkpoint_hash(&checkpoint)?;
        self.append_record(&ManifestRecord::Checkpoint { checkpoint, sig })?;

        state.pending.clear();
        state.first_index = None;
        state.prev_checkpoint_hash = this_hash;
        Ok(())
    }
}

fn load_or_create_seed(key_path: &str) -> Result<[u8; 32]> {
    if Path::new(key_path).exists() {
        let raw = fs::read_to_string(key_path)
            .with_context(|| format!("reading manifest key {key_path}"))?;
        let bytes = hex::decode(raw.trim())
            .with_context(|| format!("manifest key {key_path} is not valid hex"))?;
        let seed: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("manifest key {key_path} must be exactly 32 bytes (64 hex)"))?;
        return Ok(seed);
    }

    let seed = os_random_32();
    if let Some(parent) = Path::new(key_path).parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).ok();
        }
    }
    fs::write(key_path, hex::encode(seed))
        .with_context(|| format!("writing new manifest key {key_path}"))?;
    harden_key_perms(key_path);
    Ok(seed)
}

#[cfg(unix)]
fn harden_key_perms(path: &str) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = fs::metadata(path) {
        let mut perm = meta.permissions();
        perm.set_mode(0o600);
        let _ = fs::set_permissions(path, perm);
    }
}

#[cfg(not(unix))]
fn harden_key_perms(_path: &str) {}

fn os_random_32() -> [u8; 32] {
    let mut buf = [0u8; 32];
    if let Ok(mut f) = fs::File::open("/dev/urandom") {
        if f.read_exact(&mut buf).is_ok() {
            return buf;
        }
    }
    // Defensive fallback: never an all-zero seed even without /dev/urandom.
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9e37_79b9_7f4a_7c15)
        .to_le_bytes();
    for (i, b) in buf.iter_mut().enumerate() {
        *b = seed[i % 8] ^ (i as u8).wrapping_mul(31).wrapping_add(0x5a);
    }
    buf
}

// ---------------------------------------------------------------------------
// Verifier
// ---------------------------------------------------------------------------

/// Per-index coverage outcome for the human/CLI report.
#[derive(Debug, Clone, PartialEq)]
pub struct ManifestVerification {
    /// Hash chain re-walked cleanly.
    pub chain_intact: bool,
    pub first_broken_index: Option<u64>,
    /// Total committed entries on the chain.
    pub chain_entries: usize,
    /// Manifest/checkpoint records read.
    pub records: usize,
    /// Records whose Ed25519 signature verified against the published key.
    pub authentic_records: usize,
    /// Any record that failed authenticity (bad sig, wrong key id, or a manifest
    /// whose `entry_hash` does not match the chain).
    pub authenticity_failures: Vec<String>,
    /// Committed entry indices with no covering signature (per-action or
    /// enclosing checkpoint).
    pub uncovered_indices: Vec<u64>,
    /// Whether the verifying key was **pinned out-of-band** by the caller
    /// (`true`) or read from the in-directory `<log>.manifests.pub` (`false`).
    ///
    /// This is a trust qualifier, not a pass/fail: against an attacker who can
    /// rewrite the audit log, the in-directory pubkey is *also* attacker-writable,
    /// so an unpinned verification only proves internal self-consistency (catches
    /// accidental corruption / non-malicious regeneration). Genuine
    /// non-repudiation requires a pubkey obtained from a trusted channel.
    pub pubkey_pinned: bool,
}

impl ManifestVerification {
    /// True only when the chain is intact, every record is authentic, and every
    /// committed entry is covered. This is the CLI's exit-zero condition.
    ///
    /// Note: this does **not** require the key to be pinned — an unpinned run can
    /// still report `ok`, but only as self-consistency. Callers asserting
    /// authenticity against a malicious log-holder must also check
    /// [`Self::pubkey_pinned`].
    pub fn ok(&self) -> bool {
        self.chain_intact
            && self.authenticity_failures.is_empty()
            && self.uncovered_indices.is_empty()
    }
}

fn read_chain(audit_log_path: &str) -> Result<Vec<AuditEntry>> {
    let content = fs::read_to_string(audit_log_path).unwrap_or_default();
    let mut entries = Vec::new();
    for line in content.lines().filter(|l| !l.is_empty()) {
        entries.push(serde_json::from_str::<AuditEntry>(line)?);
    }
    Ok(entries)
}

fn parse_sig(sig_hex: &str) -> Result<Signature> {
    let raw = hex::decode(sig_hex).context("signature is not valid hex")?;
    let arr: [u8; 64] = raw
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("signature must be 64 bytes"))?;
    Ok(Signature::from_bytes(&arr))
}

/// Parse a 32-byte Ed25519 public key from a lowercase-hex string (64 chars).
pub fn pubkey_from_hex(raw: &str) -> Result<VerifyingKey> {
    let bytes = hex::decode(raw.trim()).context("manifest pubkey is not valid hex")?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("manifest pubkey must be 32 bytes (64 hex chars)"))?;
    VerifyingKey::from_bytes(&arr).map_err(|e| anyhow!("invalid Ed25519 pubkey: {e}"))
}

fn load_pubkey(pubkey_path: &str) -> Result<VerifyingKey> {
    let raw = fs::read_to_string(pubkey_path)
        .with_context(|| format!("reading manifest pubkey {pubkey_path}"))?;
    pubkey_from_hex(&raw)
}

/// Verify the manifests for an audit log: chain integrity, signature authenticity,
/// and coverage of every committed entry.
///
/// `audit_log_path` is the chain JSONL; the manifests are expected at
/// `<audit_log_path>.manifests`.
///
/// `pinned_pubkey_hex` is the **trusted** Ed25519 public key (hex), obtained
/// out-of-band. When `Some`, authenticity is checked against it and the
/// in-directory `<...>.manifests.pub` is ignored — this is the only mode that
/// gives non-repudiation against an attacker who can rewrite the log (such an
/// attacker can also rewrite the in-directory pubkey). When `None`, the verifier
/// falls back to the published in-directory pubkey for convenience (detects
/// accidental corruption only); the result's `pubkey_pinned` flag is `false`.
pub fn verify_manifests(
    audit_log_path: &str,
    pinned_pubkey_hex: Option<&str>,
) -> Result<ManifestVerification> {
    let entries = read_chain(audit_log_path)?;

    // ── 1. Chain integrity (independent re-walk; same rule as AuditLogger). ──
    let mut chain_intact = true;
    let mut first_broken_index = None;
    let mut hash_by_index = std::collections::HashMap::new();
    let mut prev = ZERO_HASH.to_string();
    for entry in &entries {
        let recomputed = AuditEntry::calculate_hash(
            entry.index,
            entry.timestamp_secs,
            &entry.prev_hash,
            &entry.observation,
            &entry.intent,
            &entry.assessment,
            &entry.decision,
        );
        if entry.prev_hash != prev || entry.hash != recomputed {
            chain_intact = false;
            first_broken_index = Some(entry.index);
            break;
        }
        hash_by_index.insert(entry.index, entry.hash.clone());
        prev = entry.hash.clone();
    }

    let manifests_path = format!("{audit_log_path}.manifests");
    let pubkey_path = format!("{manifests_path}.pub");

    let mut result = ManifestVerification {
        chain_intact,
        first_broken_index,
        chain_entries: entries.len(),
        records: 0,
        authentic_records: 0,
        authenticity_failures: Vec::new(),
        uncovered_indices: Vec::new(),
        pubkey_pinned: pinned_pubkey_hex.is_some(),
    };

    // Select the trusted key. A *pinned* key (out-of-band) is the only one that
    // resists a malicious log-holder; a bad pinned key is operator error → hard
    // fail. Otherwise fall back to the in-directory published key (convenience):
    // a missing one means provenance was never enabled, reported as a coverage
    // gap rather than aborting.
    let pubkey = match pinned_pubkey_hex {
        Some(hex_key) => pubkey_from_hex(hex_key)
            .context("invalid --manifest-pubkey (expected 64 hex chars of an Ed25519 key)")?,
        None => match load_pubkey(&pubkey_path) {
            Ok(pk) => pk,
            Err(err) => {
                result
                    .authenticity_failures
                    .push(format!("no published pubkey at {pubkey_path}: {err}"));
                for entry in &entries {
                    result.uncovered_indices.push(entry.index);
                }
                return Ok(result);
            }
        },
    };
    let expected_key_id = key_id_from_pubkey(&pubkey);

    let manifest_content = fs::read_to_string(&manifests_path).unwrap_or_default();
    let mut covered: std::collections::HashSet<u64> = std::collections::HashSet::new();
    let mut prev_checkpoint_hash = ZERO_HASH.to_string();

    for line in manifest_content.lines().filter(|l| !l.is_empty()) {
        result.records += 1;
        let record: ManifestRecord =
            serde_json::from_str(line).with_context(|| "parsing manifest record".to_string())?;

        match record {
            ManifestRecord::Action { manifest, sig } => {
                let label = format!("action@{}", manifest.index);
                let mut ok = manifest.signer_key_id == expected_key_id;
                if ok {
                    if let Ok(signature) = parse_sig(&sig) {
                        let bytes = canonical_bytes(&manifest)?;
                        ok = pubkey.verify(&bytes, &signature).is_ok();
                    } else {
                        ok = false;
                    }
                }
                // The manifest must also actually match the chain entry it claims.
                if ok {
                    match hash_by_index.get(&manifest.index) {
                        Some(h) if *h == manifest.entry_hash => {}
                        _ => ok = false,
                    }
                }
                if ok {
                    result.authentic_records += 1;
                    covered.insert(manifest.index);
                } else {
                    result.authenticity_failures.push(label);
                }
            }
            ManifestRecord::Checkpoint { checkpoint, sig } => {
                let label = format!(
                    "checkpoint@{}..{}",
                    checkpoint.first_index, checkpoint.last_index
                );
                let mut ok = checkpoint.signer_key_id == expected_key_id
                    && checkpoint.prev_checkpoint_hash == prev_checkpoint_hash;
                if ok {
                    if let Ok(signature) = parse_sig(&sig) {
                        let bytes = canonical_bytes(&checkpoint)?;
                        ok = pubkey.verify(&bytes, &signature).is_ok();
                    } else {
                        ok = false;
                    }
                }
                // Recompute the Merkle root over the chain entries in range and
                // require it to match — this is what ties the checkpoint to the
                // actual committed entries.
                if ok && chain_intact {
                    let mut range_hashes = Vec::new();
                    let mut range_ok = true;
                    for idx in checkpoint.first_index..=checkpoint.last_index {
                        match hash_by_index.get(&idx) {
                            Some(h) => range_hashes.push(h.clone()),
                            None => {
                                range_ok = false;
                                break;
                            }
                        }
                    }
                    ok = range_ok && merkle_root(&range_hashes) == checkpoint.merkle_root;
                }
                if ok {
                    result.authentic_records += 1;
                    prev_checkpoint_hash = checkpoint_hash(&checkpoint)?;
                    for idx in checkpoint.first_index..=checkpoint.last_index {
                        covered.insert(idx);
                    }
                } else {
                    result.authenticity_failures.push(label);
                }
            }
        }
    }

    // ── 3. Coverage: every committed entry must be covered by some authentic
    // record. Report gaps explicitly — never silently pass partial coverage. ──
    for entry in &entries {
        if !covered.contains(&entry.index) {
            result.uncovered_indices.push(entry.index);
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::governance::AuditLogger;

    fn unique_path(tag: &str) -> String {
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        format!("/tmp/jg_manifest_{tag}_{pid}_{nanos}")
    }

    fn cleanup(base: &str) {
        let _ = fs::remove_file(base);
        let _ = fs::remove_file(format!("{base}.db"));
        let _ = fs::remove_file(format!("{base}.manifests"));
        let _ = fs::remove_file(format!("{base}.manifests.pub"));
    }

    use crate::governance::{
        CapabilityProfile, IntentClass, ObservationRecord, PolicyDecision, RiskAssessment,
        SemanticIntent,
    };

    fn observation(uid: u32) -> ObservationRecord {
        ObservationRecord {
            pid: 42,
            start_time: 12345,
            uid,
            gid: uid,
            executable_path: Some("/bin/test-agent".to_string()),
            command_line: vec!["test-agent".to_string()],
            namespace_observed: true,
            namespace_pid_inode: Some(9999),
            namespace_net_inode: Some(8888),
            socket_peer_verified: true,
            observed_at_unix_secs: 1,
        }
    }

    fn decision_for(
        uid: u32,
    ) -> (
        ObservationRecord,
        SemanticIntent,
        RiskAssessment,
        PolicyDecision,
    ) {
        let obs = observation(uid);
        let semantic = SemanticIntent {
            class: IntentClass::ReadOnly,
            confidence: 0.9,
            risk_score: 20.0,
            signals: vec!["read_only".to_string()],
        };
        let capability = CapabilityProfile::from_observation(&obs, &[]);
        let assessment = RiskAssessment::assess(&obs, &semantic, &capability, Some(20.0));
        let decision = PolicyDecision::allow(&assessment);
        (obs, semantic, assessment, decision)
    }

    /// Append `n` real audit entries via the production logger so the chain is
    /// byte-identical to what runs in the daemon.
    fn populate_chain(audit_path: &str, n: usize) {
        let logger = AuditLogger::new(audit_path);
        for i in 0..n {
            let (obs, intent, assessment, decision) = decision_for(1000 + i as u32);
            logger.log(&obs, &intent, &assessment, &decision).unwrap();
        }
    }

    fn sign_existing_chain(audit_path: &str, key_path: &str, per_action: bool, interval: u64) {
        let signer =
            ManifestSigner::load_or_generate(key_path, audit_path, per_action, 0, interval)
                .unwrap();
        for entry in read_chain(audit_path).unwrap() {
            signer.record_entry(&entry).unwrap();
        }
        signer.flush().unwrap();
    }

    #[test]
    fn canonical_json_sorts_keys_and_is_compact() {
        let v = serde_json::json!({"b": 1, "a": {"y": 2, "x": 3}, "c": [3, 2, 1]});
        assert_eq!(
            canonical_json(&v),
            r#"{"a":{"x":3,"y":2},"b":1,"c":[3,2,1]}"#
        );
    }

    #[test]
    fn merkle_root_is_deterministic_and_order_sensitive() {
        let a = merkle_root(&["aa".into(), "bb".into(), "cc".into()]);
        let b = merkle_root(&["aa".into(), "bb".into(), "cc".into()]);
        let c = merkle_root(&["cc".into(), "bb".into(), "aa".into()]);
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(merkle_root(&[]), ZERO_HASH);
    }

    #[test]
    fn checkpoint_mode_verifies_clean() {
        let base = unique_path("clean");
        cleanup(&base);
        let key = format!("{base}.key");
        populate_chain(&base, 5);
        sign_existing_chain(&base, &key, false, 2);

        let v = verify_manifests(&base, None).unwrap();
        assert!(v.chain_intact, "chain must be intact");
        assert!(v.ok(), "clean log must verify: {v:?}");
        assert!(v.uncovered_indices.is_empty());
        cleanup(&base);
        let _ = fs::remove_file(&key);
    }

    #[test]
    fn per_action_mode_verifies_clean() {
        let base = unique_path("peraction");
        cleanup(&base);
        let key = format!("{base}.key");
        populate_chain(&base, 4);
        sign_existing_chain(&base, &key, true, 1000);

        let v = verify_manifests(&base, None).unwrap();
        assert!(v.ok(), "per-action log must verify: {v:?}");
        assert_eq!(v.uncovered_indices.len(), 0);
        cleanup(&base);
        let _ = fs::remove_file(&key);
    }

    #[test]
    fn tamper_breaks_chain_and_coverage() {
        let base = unique_path("tamper");
        cleanup(&base);
        let key = format!("{base}.key");
        populate_chain(&base, 4);
        sign_existing_chain(&base, &key, false, 2);

        // Flip a byte inside one committed entry's JSON.
        let content = fs::read_to_string(&base).unwrap();
        let mut lines: Vec<String> = content.lines().map(String::from).collect();
        lines[1] = lines[1].replacen("Allow", "Deny", 1);
        if lines[1] == content.lines().nth(1).unwrap() {
            // Decision verdict text differs by fixture; fall back to mangling the hash.
            lines[1] = lines[1].replacen("\"hash\":\"", "\"hash\":\"0", 1);
        }
        fs::write(&base, lines.join("\n") + "\n").unwrap();

        let v = verify_manifests(&base, None).unwrap();
        assert!(!v.chain_intact, "tamper must break the chain");
        assert!(!v.ok(), "tampered log must not verify");
        cleanup(&base);
        let _ = fs::remove_file(&key);
    }

    #[test]
    fn forgery_with_different_key_fails_authenticity() {
        // The whole point of the gap closure: a self-consistent chain re-signed
        // with a *different* key has an intact chain but FAILS authenticity.
        let base = unique_path("forge");
        cleanup(&base);
        let genuine_key = format!("{base}.genuine.key");
        let attacker_key = format!("{base}.attacker.key");

        populate_chain(&base, 3);
        // Genuine signer publishes the real pubkey + manifests.
        sign_existing_chain(&base, &genuine_key, false, 2);
        let genuine = verify_manifests(&base, None).unwrap();
        assert!(genuine.ok(), "genuine log must verify first: {genuine:?}");

        // Attacker regenerates a fully self-consistent set of manifests with their
        // own key, overwriting the manifests file — but cannot overwrite the
        // published genuine pubkey held by the verifier.
        let pub_backup = fs::read_to_string(format!("{base}.manifests.pub")).unwrap();
        let _ = fs::remove_file(format!("{base}.manifests"));
        let attacker = ManifestSigner::load_or_generate(&attacker_key, &base, false, 0, 2).unwrap();
        for entry in read_chain(&base).unwrap() {
            attacker.record_entry(&entry).unwrap();
        }
        attacker.flush().unwrap();
        // Restore the genuine published pubkey the verifier trusts.
        fs::write(format!("{base}.manifests.pub"), pub_backup).unwrap();

        let forged = verify_manifests(&base, None).unwrap();
        assert!(forged.chain_intact, "chain itself is still self-consistent");
        assert!(
            !forged.ok(),
            "forged manifests must fail authenticity against the genuine pubkey: {forged:?}"
        );
        assert!(!forged.authenticity_failures.is_empty());

        cleanup(&base);
        let _ = fs::remove_file(&genuine_key);
        let _ = fs::remove_file(&attacker_key);
    }

    #[test]
    fn swapped_pubkey_forgery_defeated_only_by_pinned_key() {
        // JG-RT-026: an attacker who can rewrite the audit log can ALSO rewrite the
        // in-directory `<log>.manifests.pub`. If the verifier trusts that in-dir key
        // (the `None` / convenience path), a fully self-consistent forgery — manifests
        // re-signed with the attacker's key AND that key published as the pubkey —
        // passes. Genuine non-repudiation requires PINNING the real key out-of-band.
        let base = unique_path("swapkey");
        cleanup(&base);
        let genuine_key = format!("{base}.genuine.key");
        let attacker_key = format!("{base}.attacker.key");

        populate_chain(&base, 3);
        let genuine_signer =
            ManifestSigner::load_or_generate(&genuine_key, &base, false, 0, 2).unwrap();
        for entry in read_chain(&base).unwrap() {
            genuine_signer.record_entry(&entry).unwrap();
        }
        genuine_signer.flush().unwrap();
        let genuine_pubkey_hex = genuine_signer.public_key_hex();

        // Attacker rewrites BOTH the manifests and the published pubkey.
        let _ = fs::remove_file(format!("{base}.manifests"));
        let attacker = ManifestSigner::load_or_generate(&attacker_key, &base, false, 0, 2).unwrap();
        for entry in read_chain(&base).unwrap() {
            attacker.record_entry(&entry).unwrap();
        }
        attacker.flush().unwrap();
        // attacker.load_or_generate already overwrote `<base>.manifests.pub` with
        // the attacker key — the in-dir pubkey is now attacker-controlled.

        // Convenience mode (None) trusts the in-dir key → the forgery LOOKS ok, but
        // the result is explicitly flagged as not pinned (self-consistency only).
        let unpinned = verify_manifests(&base, None).unwrap();
        assert!(
            unpinned.ok(),
            "self-consistent forgery passes the convenience path: {unpinned:?}"
        );
        assert!(
            !unpinned.pubkey_pinned,
            "convenience path must report pubkey_pinned=false"
        );

        // Pinned to the genuine key (out-of-band) → attacker signatures fail.
        let pinned = verify_manifests(&base, Some(&genuine_pubkey_hex)).unwrap();
        assert!(pinned.pubkey_pinned);
        assert!(
            !pinned.ok(),
            "pinned genuine key must reject attacker-signed manifests: {pinned:?}"
        );
        assert!(!pinned.authenticity_failures.is_empty());

        cleanup(&base);
        let _ = fs::remove_file(&genuine_key);
        let _ = fs::remove_file(&attacker_key);
    }

    #[test]
    fn erasure_keeps_chain_and_signatures_valid() {
        // Crypto-shredding deletes only audit_pii; signatures cover the redacted
        // chain bytes, so verification is unchanged after an erasure.
        let base = unique_path("erase");
        cleanup(&base);
        let key = format!("{base}.key");
        let logger = AuditLogger::new(&base);
        let (obs, intent, assessment, decision) = decision_for(4242);
        logger.log(&obs, &intent, &assessment, &decision).unwrap();
        logger.log(&obs, &intent, &assessment, &decision).unwrap();
        sign_existing_chain(&base, &key, true, 2);

        let before = verify_manifests(&base, None).unwrap();
        assert!(before.ok(), "must verify before erasure: {before:?}");

        // Erase the subject's PII (no-op on the chain bytes by design).
        let _ = logger.erase_uid(4242);

        let after = verify_manifests(&base, None).unwrap();
        assert!(after.ok(), "must still verify after erasure: {after:?}");
        assert_eq!(before.chain_intact, after.chain_intact);
        cleanup(&base);
        let _ = fs::remove_file(&key);
    }
}
