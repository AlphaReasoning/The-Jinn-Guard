/// Jinn Guard — Fleet Policy Distribution (Item 4)
///
/// Pulls a signed, versioned policy bundle from a central policy server,
/// verifies its HMAC-SHA256 signature, enforces a minimum version to prevent
/// rollback attacks, and reloads the daemon's active policy in-place.
///
/// Bundle format (JSON):
/// ```json
/// {
///   "version": 42,
///   "issued_at": 1717000000,
///   "policy_yaml": "<escaped YAML string>",
///   "signature": "<hex HMAC-SHA256 over version+issued_at+policy_yaml>"
/// }
/// ```
///
/// The daemon exposes `--fleet-policy-url <url>` CLI flag and optional
/// `fleet_policy_url` + `fleet_policy_min_version` fields in `policy.yaml`.
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::time::Duration;

pub const MAX_FLEET_BUNDLE_BYTES: usize = 4 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Bundle types
// ---------------------------------------------------------------------------

/// A signed, versioned policy bundle pulled from the fleet policy server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyBundle {
    /// Monotonically increasing version number.
    pub version: u64,
    /// Unix timestamp at which this bundle was issued.
    pub issued_at: u64,
    /// Full policy.yaml contents as a string.
    pub policy_yaml: String,
    /// HMAC-SHA256 signature hex-encoded over the canonical bytes.
    pub signature: String,
}

impl PolicyBundle {
    /// Canonical bytes signed by the issuer.
    ///
    /// Format: `version={v}&issued_at={t}&sha256={sha256(policy_yaml)}`
    pub fn canonical_bytes(&self) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let policy_hash = hex::encode(Sha256::digest(self.policy_yaml.as_bytes()));
        format!(
            "version={}&issued_at={}&sha256={}",
            self.version, self.issued_at, policy_hash
        )
        .into_bytes()
    }

    /// Verify the bundle's HMAC-SHA256 signature against `secret`.
    pub fn verify(&self, secret: &[u8]) -> bool {
        use hmac::{Hmac, KeyInit, Mac};
        use sha2::Sha256;
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = match HmacSha256::new_from_slice(secret) {
            Ok(m) => m,
            Err(_) => return false,
        };
        mac.update(&self.canonical_bytes());
        let expected = hex::encode(mac.finalize().into_bytes());
        constant_time_eq::constant_time_eq(expected.as_bytes(), self.signature.as_bytes())
    }

    /// Sign this bundle and store the result in `self.signature`.
    pub fn sign(&mut self, secret: &[u8]) {
        use hmac::{Hmac, KeyInit, Mac};
        use sha2::Sha256;
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(secret).expect("valid key");
        mac.update(&self.canonical_bytes());
        self.signature = hex::encode(mac.finalize().into_bytes());
    }
}

/// Outcome of evaluating an incoming bundle against the daemon's current state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BundleDecision {
    /// Newer, correctly-signed bundle — apply and ratchet the rollback floor.
    Apply,
    /// Version is below the rollback floor — refuse (rollback / replay attack).
    RejectRollback,
    /// Signature does not verify against the fleet key — refuse (tampered/forged).
    RejectBadSignature,
    /// Already running this exact version — no-op.
    AlreadyApplied,
}

/// Decide what to do with a freshly-fetched bundle, given the daemon's current
/// rollback floor (`min_version`) and the version it is already enforcing
/// (`applied_version`). This is the single source of truth for the fleet
/// accept/reject policy; the daemon's refresh loop calls it so the behaviour is
/// exactly what these unit tests cover.
///
/// Rollback is checked **before** signature on purpose: a stale version is
/// rejected as a rollback regardless of whether its signature is also bad, so a
/// replay of an old (once-valid) bundle can never be applied. Both checks must
/// pass before a bundle is eligible to apply, so the ordering is safe either way.
pub fn evaluate_bundle(
    bundle: &PolicyBundle,
    min_version: u64,
    applied_version: u64,
    key: &[u8],
) -> BundleDecision {
    if bundle.version < min_version {
        return BundleDecision::RejectRollback;
    }
    if !bundle.verify(key) {
        return BundleDecision::RejectBadSignature;
    }
    if bundle.version == applied_version {
        return BundleDecision::AlreadyApplied;
    }
    BundleDecision::Apply
}

// ---------------------------------------------------------------------------
// Fleet policy fetcher
// ---------------------------------------------------------------------------

/// Configuration for the fleet policy pull client.
#[derive(Debug, Clone)]
pub struct FleetPolicyConfig {
    /// URL of the policy bundle endpoint (HTTP or HTTPS GET).
    pub url: String,
    /// The minimum bundle version this daemon will accept.
    pub min_version: u64,
    /// HMAC secret used to verify the bundle signature.
    pub hmac_secret: Vec<u8>,
    /// How long to wait for the HTTP response.
    pub fetch_timeout_secs: u64,
}

/// Result returned from a successful fleet policy pull.
pub struct FleetPolicyPullResult {
    pub bundle: PolicyBundle,
    /// The policy.yaml content, ready for parsing.
    pub policy_yaml: String,
}

/// Fetch and verify a policy bundle from the fleet policy server.
///
/// Returns `Err` when:
/// - The HTTP request fails.
/// - The bundle signature is invalid.
/// - `bundle.version < config.min_version` (rollback protection).
/// - The response is malformed JSON.
pub fn fetch_policy_bundle(config: &FleetPolicyConfig) -> Result<FleetPolicyPullResult> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(config.fetch_timeout_secs))
        .build()
        .map_err(|e| anyhow!("HTTP client build: {e}"))?;

    let resp = client
        .get(&config.url)
        .header("accept", "application/json")
        .header("user-agent", "jinnguard-fleet-client/1.0")
        .send()
        .map_err(|e| anyhow!("Fleet policy fetch failed: {e}"))?;

    if !resp.status().is_success() {
        return Err(anyhow!(
            "Fleet policy server returned {}: {}",
            resp.status(),
            resp.url().as_str()
        ));
    }

    let body = read_blocking_response_limited(resp, MAX_FLEET_BUNDLE_BYTES)?;
    let bundle: PolicyBundle = serde_json::from_str(&body)
        .map_err(|e| anyhow!("Fleet policy bundle parse failed: {e}"))?;

    // Rollback protection: reject bundles older than minimum accepted version.
    if bundle.version < config.min_version {
        return Err(anyhow!(
            "Fleet policy bundle version {} is below minimum {}",
            bundle.version,
            config.min_version
        ));
    }

    // Signature verification.
    if !bundle.verify(&config.hmac_secret) {
        return Err(anyhow!(
            "Fleet policy bundle signature INVALID (version={})",
            bundle.version
        ));
    }

    let policy_yaml = bundle.policy_yaml.clone();
    println!(
        "[fleet_policy] pulled bundle version={} issued_at={} ({} bytes)",
        bundle.version,
        bundle.issued_at,
        policy_yaml.len()
    );

    Ok(FleetPolicyPullResult {
        bundle,
        policy_yaml,
    })
}

fn read_blocking_response_limited(
    mut response: reqwest::blocking::Response,
    limit: usize,
) -> Result<String> {
    if let Some(len) = response.content_length() {
        if len > limit as u64 {
            return Err(anyhow!(
                "Fleet policy response declares {len} bytes; limit is {limit}"
            ));
        }
    }

    let mut body = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = response
            .read(&mut buf)
            .map_err(|e| anyhow!("Fleet policy body read failed: {e}"))?;
        if n == 0 {
            break;
        }
        if body.len().saturating_add(n) > limit {
            return Err(anyhow!("Fleet policy response exceeds limit {limit} bytes"));
        }
        body.extend_from_slice(&buf[..n]);
    }

    String::from_utf8(body).map_err(|e| anyhow!("Fleet policy response is not UTF-8: {e}"))
}

/// Persist a bundle to a local cache file for offline operation.
///
/// The cache is a plain JSON file; on restart the daemon reads it if the fleet
/// server is unreachable and no newer bundle has been delivered.
pub fn cache_bundle(bundle: &PolicyBundle, cache_path: &str) -> Result<()> {
    let json =
        serde_json::to_string_pretty(bundle).map_err(|e| anyhow!("Bundle serialize: {e}"))?;
    let tmp = format!("{cache_path}.tmp");
    std::fs::write(&tmp, &json).map_err(|e| anyhow!("Bundle cache write {tmp}: {e}"))?;
    std::fs::rename(&tmp, cache_path).map_err(|e| anyhow!("Bundle cache rename: {e}"))?;
    Ok(())
}

/// Load the most recent cached bundle.
pub fn load_cached_bundle(cache_path: &str) -> Option<PolicyBundle> {
    let content = std::fs::read_to_string(cache_path).ok()?;
    serde_json::from_str(&content).ok()
}

// ---------------------------------------------------------------------------
// Item 5: Cross-Machine Lineage — LineageSummary embedded in DelegationTokens
// ---------------------------------------------------------------------------

/// A compact summary of an agent's behavioral history on one machine.
///
/// This is embedded in a `DelegationToken` so that a receiving machine can
/// seed its local lineage registry with real behavioral data rather than
/// starting from scratch.
///
/// The summary is part of the signed token canonical bytes, so it cannot
/// be forged.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LineageSummary {
    /// Total number of governance decisions seen on the originating machine.
    pub decisions_seen: u64,
    /// Maximum fused risk score observed across all decisions.
    pub max_assessed_risk: f64,
    /// Unix timestamp of the agent's first appearance on the originating machine.
    pub first_seen_unix_secs: u64,
    /// Total DENY decisions on the originating machine.
    pub denied_count: u64,
    /// Originating machine identifier (hostname or deployment ID).
    pub origin_machine_id: String,
}

impl LineageSummary {
    /// Compute an effective trust penalty from this summary.
    ///
    /// The receiving machine applies this penalty to the initial trust score
    /// when seeding the local lineage registry.
    pub fn trust_penalty(&self) -> f64 {
        // Penalty grows with: denial rate, max risk, and short history.
        let denial_rate = if self.decisions_seen > 0 {
            self.denied_count as f64 / self.decisions_seen as f64
        } else {
            0.0
        };
        // Denial rate contributes up to 30 points, max risk up to 40 points.
        let penalty = denial_rate * 30.0 + self.max_assessed_risk * 0.40;
        penalty.clamp(0.0, 70.0)
    }

    /// Seed a `governance::AgentLineage`-compatible record using this summary.
    ///
    /// Returns `(decisions_seen, max_assessed_risk, initial_trust_score)`.
    pub fn seed_values(&self) -> (u64, f64, f64) {
        let initial_trust = (100.0 - self.trust_penalty()).clamp(5.0, 100.0);
        (self.decisions_seen, self.max_assessed_risk, initial_trust)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SECRET: &[u8] = b"fleet_policy_test_secret_32bytes____";

    fn make_bundle(version: u64) -> PolicyBundle {
        let mut b = PolicyBundle {
            version,
            issued_at: 1_717_000_000,
            policy_yaml: "global_safety_ceiling: 80.0\ndeny_anonymous_agents: true\n".to_string(),
            signature: String::new(),
        };
        b.sign(TEST_SECRET);
        b
    }

    #[test]
    fn test_bundle_sign_and_verify() {
        let bundle = make_bundle(42);
        assert!(bundle.verify(TEST_SECRET), "signature should be valid");
    }

    #[test]
    fn test_bundle_tampered_policy_fails_verify() {
        let mut bundle = make_bundle(42);
        bundle.policy_yaml.push_str("\nmalicious: true\n");
        assert!(!bundle.verify(TEST_SECRET), "tampered bundle should fail");
    }

    #[test]
    fn test_bundle_wrong_secret_fails_verify() {
        let bundle = make_bundle(42);
        assert!(!bundle.verify(b"wrong_secret"), "wrong secret should fail");
    }

    // ── evaluate_bundle: the daemon's accept/reject decision ──────────────
    // These cover the exact path the refresh loop runs (it calls this fn).

    #[test]
    fn test_evaluate_apply_forward() {
        // Newer, correctly-signed bundle than what we run -> apply.
        let bundle = make_bundle(6);
        let d = evaluate_bundle(&bundle, /*min*/ 5, /*applied*/ 3, TEST_SECRET);
        assert_eq!(d, BundleDecision::Apply);
    }

    #[test]
    fn test_evaluate_reject_rollback() {
        // Validly-signed but BELOW the rollback floor -> refuse (replay attack).
        let bundle = make_bundle(3);
        let d = evaluate_bundle(&bundle, /*min*/ 5, /*applied*/ 0, TEST_SECRET);
        assert_eq!(d, BundleDecision::RejectRollback);
    }

    #[test]
    fn test_evaluate_reject_bad_signature() {
        // New enough to clear the floor, but signed with the wrong key -> refuse.
        let bundle = make_bundle(6);
        let d = evaluate_bundle(&bundle, /*min*/ 5, /*applied*/ 0, b"wrong_key");
        assert_eq!(d, BundleDecision::RejectBadSignature);
    }

    #[test]
    fn test_evaluate_already_applied_is_noop() {
        // Exactly the version we already enforce -> no-op (no needless reload).
        let bundle = make_bundle(5);
        let d = evaluate_bundle(&bundle, /*min*/ 5, /*applied*/ 5, TEST_SECRET);
        assert_eq!(d, BundleDecision::AlreadyApplied);
    }

    #[test]
    fn test_evaluate_rollback_takes_precedence_over_bad_signature() {
        // A stale bundle with a bad signature is reported as a rollback: an old
        // bundle can never be applied regardless of how it's (mis)signed.
        let mut bundle = make_bundle(3);
        bundle.signature = "deadbeef".to_string(); // also invalid
        let d = evaluate_bundle(&bundle, /*min*/ 5, /*applied*/ 0, TEST_SECRET);
        assert_eq!(d, BundleDecision::RejectRollback);
    }

    #[test]
    fn fetch_policy_bundle_rejects_oversized_response_without_content_length() {
        use std::io::{Read as _, Write as _};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request_buf = [0u8; 512];
            let _ = stream.read(&mut request_buf);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n")
                .unwrap();
            let body = vec![b'a'; MAX_FLEET_BUNDLE_BYTES + 1];
            let _ = stream.write_all(&body);
        });

        let cfg = FleetPolicyConfig {
            url: format!("http://{addr}/bundle"),
            min_version: 0,
            hmac_secret: TEST_SECRET.to_vec(),
            fetch_timeout_secs: 5,
        };
        let err = match fetch_policy_bundle(&cfg) {
            Ok(_) => panic!("oversized fleet response must be rejected"),
            Err(err) => err.to_string(),
        };

        assert!(err.contains("exceeds limit"), "got: {err}");
        handle.join().unwrap();
    }

    #[test]
    fn test_lineage_summary_trust_penalty_zero_denials() {
        let summary = LineageSummary {
            decisions_seen: 100,
            max_assessed_risk: 20.0,
            first_seen_unix_secs: 0,
            denied_count: 0,
            origin_machine_id: "machine-a".to_string(),
        };
        // 0% denial rate, 20 * 0.4 = 8 penalty
        assert!((summary.trust_penalty() - 8.0).abs() < 0.01);
    }

    #[test]
    fn test_lineage_summary_high_denial_rate() {
        let summary = LineageSummary {
            decisions_seen: 100,
            max_assessed_risk: 50.0,
            first_seen_unix_secs: 0,
            denied_count: 50, // 50% denial rate
            origin_machine_id: "machine-b".to_string(),
        };
        // 50% * 30 + 50 * 0.4 = 15 + 20 = 35
        assert!((summary.trust_penalty() - 35.0).abs() < 0.01);
    }

    #[test]
    fn test_lineage_summary_seed_values() {
        let summary = LineageSummary {
            decisions_seen: 50,
            max_assessed_risk: 30.0,
            first_seen_unix_secs: 1_000_000,
            denied_count: 5, // 10% denial rate
            origin_machine_id: "machine-c".to_string(),
        };
        let (decisions, max_risk, trust) = summary.seed_values();
        assert_eq!(decisions, 50);
        assert_eq!(max_risk, 30.0);
        // penalty = 0.1 * 30 + 30 * 0.4 = 3 + 12 = 15 → trust = 85
        assert!((trust - 85.0).abs() < 0.01, "trust={trust}");
    }
}
