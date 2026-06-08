// ts_cli/src/main.rs — Jinn Guard Daemon
//
// Architecture:
//   • UDS server: receives framed HMAC-signed ClientProposal packets
//   • MCP gateway: HTTP/1.1 TCP proxy for JSON-RPC tool calls
//   • Policy hot-reload: SIGHUP + optional periodic fetch from remote server
//   • eBPF LSM: optional kernel telemetry (feature = "kernel_telemetry")

#![cfg(target_os = "linux")]

pub mod ebpf_monitor;
pub mod fleet_policy;
pub mod governance;
pub mod mcp_gateway;

use anyhow::Result;
use clap::Parser;
use governance::{
    AgentLineage, AuditLogger, CapabilityProfile, ClientProposal, CombinedSemanticService,
    ConstraintSet, ExecutionBroker, ExecutionRequest, LineageRegistry, ObservationRecord,
    PolicyDecision, ProposedAction, RiskAssessment, SemanticAnalysisService,
};
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex};
#[cfg(feature = "kernel_telemetry")]
use std::thread;
#[cfg(feature = "kernel_telemetry")]
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;
use tokio::signal::unix::{signal, SignalKind};
use ts_checker::PolicyEngine;
use z3::{Config as Z3Config, Context as Z3Context};

#[cfg(feature = "kernel_telemetry")]
use ebpf_monitor::{LsmRequest, LsmRequestType, Verdict};

type HmacSha256 = Hmac<Sha256>;

// TelemetryStore maps kernel PID → list of kernel telemetry events
// Feature-gated: in non-kernel-telemetry builds this is a stub.
pub(crate) type TelemetryStore = Arc<Mutex<HashMap<u32, Vec<KernelTelemetryEvent>>>>;

#[derive(Debug, Clone)]
pub(crate) struct KernelTelemetryEvent {
    pub event_type: String,
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
    /// Remote policy server URL (HTTPS)
    #[arg(long)]
    policy_server: Option<String>,
    /// Policy refresh interval in seconds
    #[arg(long, default_value_t = 60)]
    policy_refresh_secs: u64,
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
    pub network_policy: NetworkPolicy,
    pub runtime_policy: RuntimePolicy,
    pub fleet_policy_min_version: u64,
    pub accept_cross_machine_lineage: bool,
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
}

fn default_ceiling() -> f64 {
    95.0
}

fn load_policy_from_path(policy_file: &str) -> PolicyConfig {
    if let Ok(content) = fs::read_to_string(policy_file) {
        if let Ok(yaml) = serde_yaml::from_str::<PolicyYaml>(&content) {
            let agent_nodes: HashMap<String, AgentNodePolicy> = yaml
                .agent_nodes
                .into_iter()
                .map(|n| (n.id.clone(), n))
                .collect();
            return PolicyConfig {
                upper_safety_boundary: yaml.global_safety_ceiling,
                minimum_trust_score: 100.0 - yaml.global_safety_ceiling,
                agent_nodes,
                // Support both field names for compatibility
                deny_anonymous_agents: yaml.deny_anonymous_agents || yaml.deny_anonymous,
                allow_anonymous_override: false,
                network_policy: yaml.network_policy,
                runtime_policy: yaml.runtime_policy,
                fleet_policy_min_version: yaml.fleet_policy_min_version,
                accept_cross_machine_lineage: yaml.accept_cross_machine_lineage,
            };
        }
    }
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
        eprintln!(
            "FATAL: No HMAC secret. Use --secret-file or configure the kernel keyring."
        );
        std::process::exit(1);
    })
}

// ---------------------------------------------------------------------------
// HMAC envelope verification
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct SignedEnvelope {
    payload: String,
    signature: String,
}

fn verify_envelope(envelope: &SignedEnvelope, secret: &[u8]) -> bool {
    let provided = match hex::decode(envelope.signature.trim()) {
        Ok(sig) => sig,
        Err(_) => return false,
    };
    let mut mac = match HmacSha256::new_from_slice(secret) {
        Ok(m) => m,
        Err(_) => return false,
    };
    mac.update(envelope.payload.as_bytes());
    let expected = mac.finalize().into_bytes();
    constant_time_eq::constant_time_eq(expected.as_slice(), provided.as_slice())
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
        ProposedAction::ShellCommand { command } => match Command::new("/bin/sh").arg("-c").arg(command).output() {
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
        },
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

// ---------------------------------------------------------------------------
// Policy decision (mid-band CONSTRAIN + hard ceiling)
// ---------------------------------------------------------------------------

pub(crate) fn policy_decision(
    assessment: &RiskAssessment,
    policy: &PolicyConfig,
) -> PolicyDecision {
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

async fn write_framed_response(
    stream: &mut tokio::net::UnixStream,
    version: u8,
    data: &[u8],
) -> std::io::Result<()> {
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
    secret_file: Option<String>,
    nonce_store: Arc<Mutex<HashSet<(String, u64)>>>,
) {
    let Some(peer) = get_socket_peer_credentials(&stream) else {
        println!("[deny] failed to resolve kernel peer credentials");
        return;
    };
    let observation = ObservationRecord::from_peer(peer.pid, peer.uid, peer.gid);

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
        if let Err(e) = stream.read_exact(&mut header).await {
            println!("[deny] failed to read protocol header: {}", e);
            return;
        }

        let length = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize;
        let version = header[4];

        if version != 1 {
            deny(&mut stream, b"SIGNAL: DENY_BAD_VERSION\n").await;
            return;
        }

        // STEP 2: Read payload bytes of declared length.
        if length > 4 * 1024 * 1024 {
            deny(&mut stream, b"SIGNAL: DENY_PAYLOAD_TOO_LARGE\n").await;
            return;
        }

        let mut buffer = vec![0u8; length];
        if let Err(e) = stream.read_exact(&mut buffer).await {
            println!("[deny] failed to read payload: {}", e);
            return;
        }

        let raw_wire_packet = match std::str::from_utf8(&buffer) {
            Ok(s) => s,
            Err(_) => {
                deny(&mut stream, b"SIGNAL: DENY_ENCODING_ERROR\n").await;
                return;
            }
        };

        // STEP 3: Parse outer SignedEnvelope.
        let envelope: SignedEnvelope = match serde_json::from_str(raw_wire_packet) {
            Ok(e) => e,
            Err(_) => {
                deny(&mut stream, b"SIGNAL: DENY_MALFORMED_PAYLOAD\n").await;
                return;
            }
        };

        // STEP 4: Verify HMAC signature against the inner payload string.
        let secret = load_secret_from_file(secret_file.as_deref());
        if !verify_envelope(&envelope, &secret) {
            println!("[deny] pid={} HMAC verification failed", observation.pid);
            deny(&mut stream, b"SIGNAL: DENY_TAMPERED_TOKEN\n").await;
            return;
        }

        // STEP 5: Parse the inner proposal and extract agent_id from the raw JSON.
        let proposal: ClientProposal = match serde_json::from_str(&envelope.payload) {
            Ok(p) => p,
            Err(_) => {
                deny(&mut stream, b"SIGNAL: DENY_MALFORMED_PAYLOAD\n").await;
                return;
            }
        };

        let raw_payload_value: Value = match serde_json::from_str(&envelope.payload) {
            Ok(v) => v,
            Err(_) => {
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

        // STEP 6: Replay detection.
        let agent_key = agent_id_opt
            .clone()
            .unwrap_or_else(|| "anonymous".to_string());
        let replay_detected = {
            let mut seen = nonce_store.lock().unwrap();
            !seen.insert((agent_key.clone(), proposal.sequence_counter))
        };
        if replay_detected {
            println!(
                "[deny] pid={} replay attack detected agent={} seq={}",
                observation.pid, agent_key, proposal.sequence_counter
            );
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
                deny(&mut stream, b"SIGNAL: DENY_UNKNOWN_AGENT_ID\n").await;
                return;
            }
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
                deny(&mut stream, b"SIGNAL: DENY_DELEGATION_INVALID\n").await;
                return;
            }

            println!(
                "[deny] pid={} unsupported delegation token rejected",
                observation.pid
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
                    let placeholder_assessment = RiskAssessment {
                        observed_risk: 0.0,
                        semantic_risk: 0.0,
                        topology_risk: 0.0,
                        declared_risk: None,
                        fused_risk: 0.0,
                        trust_score: 100.0,
                        reasons: vec!["quota_placeholder_assessment".to_string()],
                    };
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
                    deny(&mut stream, b"SIGNAL: DENY_QUOTA_EXHAUSTED\n").await;
                    return;
                }
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
            let invariant_decision = PolicyDecision::deny("policy_invariant_violated", &assessment);
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
            decision = PolicyDecision::deny("risk_ceiling_exceeded", &assessment);
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

        let broker_result = if current_policy
            .runtime_policy
            .require_brokered_execution
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
    std::env::var(name)
        .map(|value| {
            let value = value.trim();
            value == "1" || value.eq_ignore_ascii_case("true")
        })
        .unwrap_or(false)
}

fn enterprise_kernel_telemetry_required() -> bool {
    env_flag_enabled("JINNGUARD_ENTERPRISE")
}

fn jinnguard_safe_mode_enabled() -> bool {
    env_flag_enabled("JINNGUARD_SAFE_MODE")
}

#[cfg(feature = "kernel_telemetry")]
const BOOTSTRAP_ALLOWED_EXECUTABLES: &[&str] = &[
    "/usr/bin/sudo",
    "/usr/bin/systemctl",
    "/usr/bin/journalctl",
    "/usr/bin/bash",
    "/bin/bash",
    "/usr/bin/env",
    "/usr/bin/clear",
    "/usr/bin/sleep",
];

#[cfg(feature = "kernel_telemetry")]
fn start_lsm_verdict_loop(
    active_policy: Arc<Mutex<PolicyConfig>>,
    telemetry_store: TelemetryStore,
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
    monitor.configure_policy(&policy_snapshot, safe_mode).map_err(|err| {
        anyhow::anyhow!("fail-closed: failed to configure in-kernel LSM policy maps: {err}")
    })?;

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

        for request in requests {
            let policy_snapshot = active_policy.lock().unwrap().clone();
            let verdict = lsm_policy_verdict(&request, &policy_snapshot, safe_mode);
            let denied = matches!(verdict, Verdict::Deny);

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
fn lsm_policy_verdict(
    request: &LsmRequest,
    policy: &PolicyConfig,
    safe_mode: bool,
) -> Verdict {
    if safe_mode {
        return Verdict::Allow;
    }

    match request.req_type {
        LsmRequestType::Connect | LsmRequestType::SendMsg => {
            lsm_network_verdict(request, &policy.network_policy)
        }
        LsmRequestType::Execve => lsm_exec_verdict(request, policy),
        LsmRequestType::InodeCreate => {
            lsm_path_denylist_verdict(request.effective_path(), policy, |node| {
                &node.denied_write_paths
            })
        }
        LsmRequestType::InodeUnlink => {
            lsm_path_denylist_verdict(request.effective_path(), policy, |node| {
                &node.denied_unlink_paths
            })
        }
    }
}

#[cfg(feature = "kernel_telemetry")]
fn lsm_network_verdict(request: &LsmRequest, policy: &NetworkPolicy) -> Verdict {
    let resource = request.effective_path();
    if request.family as i32 == libc::AF_UNIX {
        if policy.default_deny
            && !policy
                .allowed_unix_sockets
                .iter()
                .any(|allowed| resource.starts_with(allowed))
        {
            return Verdict::Deny;
        }
        return Verdict::Allow;
    }

    let resource_ip = network_resource_ip(resource);
    if matches_network_entry(resource, resource_ip, &policy.denied_ips) {
        return Verdict::Deny;
    }
    if policy.default_deny && !matches_network_entry(resource, resource_ip, &policy.allowed_ips) {
        return Verdict::Deny;
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

#[cfg(feature = "kernel_telemetry")]
fn lsm_exec_verdict(request: &LsmRequest, policy: &PolicyConfig) -> Verdict {
    let path = request.effective_path();
    if BOOTSTRAP_ALLOWED_EXECUTABLES
        .iter()
        .any(|allowed| path == *allowed)
    {
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
        return Verdict::Deny;
    }
    Verdict::Allow
}

#[cfg(feature = "kernel_telemetry")]
fn lsm_path_denylist_verdict<F>(path: &str, policy: &PolicyConfig, denylist: F) -> Verdict
where
    F: Fn(&AgentNodePolicy) -> &Vec<String>,
{
    if policy
        .agent_nodes
        .values()
        .any(|node| path_matches_any(path, denylist(node)))
    {
        return Verdict::Deny;
    }
    Verdict::Allow
}

#[cfg(feature = "kernel_telemetry")]
fn path_matches_any(path: &str, patterns: &[String]) -> bool {
    patterns.iter().any(|pattern| {
        let pattern = pattern.trim();
        !pattern.is_empty() && (path == pattern || path.starts_with(pattern.trim_end_matches('/')))
    })
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
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

    // Remove stale socket.
    if Path::new(&args.socket_path).exists() {
        fs::remove_file(&args.socket_path)?;
    }

    // Load secret.
    let secret = Arc::new(load_secret_from_file(args.secret_file.as_deref()));

    // Load initial policy.
    let mut initial_policy = load_policy_from_path(&args.policy_file);
    initial_policy.allow_anonymous_override = args.allow_anonymous;
    let active_policy = Arc::new(Mutex::new(initial_policy));

    // Shared state.
    let registry_store = Arc::new(Mutex::new(LineageRegistry::load_or_create(
        &args.lineage_file,
    )));
    let audit_logger = Arc::new(AuditLogger::new(&args.audit_log));
    let telemetry_store: TelemetryStore = Arc::new(Mutex::new(HashMap::new()));
    let nonce_store: Arc<Mutex<HashSet<(String, u64)>>> = Arc::new(Mutex::new(HashSet::new()));

    eprintln!("[startup] initializing LSM verdict loop");
    start_lsm_verdict_loop(Arc::clone(&active_policy), Arc::clone(&telemetry_store))?;
    eprintln!("[startup] LSM verdict loop initialization complete");

    // ── SIGHUP: hot-reload policy ─────────────────────────────────────────
    {
        let policy_file = args.policy_file.clone();
        let active_policy = Arc::clone(&active_policy);
        let allow_anonymous = args.allow_anonymous;
        tokio::spawn(async move {
            let mut hup = signal(SignalKind::hangup()).expect("failed to install SIGHUP handler");
            loop {
                hup.recv().await;
                println!(
                    "[config] SIGHUP received — reloading policy from {}",
                    policy_file
                );
                let mut new_policy = load_policy_from_path(&policy_file);
                new_policy.allow_anonymous_override = allow_anonymous;
                *active_policy.lock().unwrap() = new_policy;
                println!("[config] Policy reloaded.");
            }
        });
    }

    // ── Optional: remote policy refresh ──────────────────────────────────
    if let Some(policy_url) = args.policy_server.clone() {
        let active_policy = Arc::clone(&active_policy);
        let refresh_secs = args.policy_refresh_secs;
        let allow_anonymous = args.allow_anonymous;
        tokio::spawn(async move {
            let mut etag: Option<String> = None;
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(refresh_secs)).await;
                // Build a reqwest client and fetch with If-None-Match
                let client = match reqwest::Client::builder()
                    .danger_accept_invalid_certs(false)
                    .build()
                {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("[policy-server] failed to build HTTP client: {e}");
                        continue;
                    }
                };
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
                        match resp.text().await {
                            Ok(body) => {
                                if let Ok(new_policy) = serde_yaml::from_str::<PolicyYaml>(&body) {
                                    let nodes: HashMap<String, AgentNodePolicy> = new_policy
                                        .agent_nodes
                                        .into_iter()
                                        .map(|n| (n.id.clone(), n))
                                        .collect();
                                    let cfg = PolicyConfig {
                                        upper_safety_boundary: new_policy.global_safety_ceiling,
                                        minimum_trust_score: 100.0
                                            - new_policy.global_safety_ceiling,
                                        agent_nodes: nodes,
                                        deny_anonymous_agents: new_policy.deny_anonymous_agents
                                            || new_policy.deny_anonymous,
                                        allow_anonymous_override: allow_anonymous,
                                        network_policy: new_policy.network_policy,
                                        runtime_policy: new_policy.runtime_policy,
                                        fleet_policy_min_version: new_policy
                                            .fleet_policy_min_version,
                                        accept_cross_machine_lineage: new_policy
                                            .accept_cross_machine_lineage,
                                    };
                                    *active_policy.lock().unwrap() = cfg;
                                    etag = new_etag;
                                    println!(
                                        "[policy-server] Policy refreshed from {}",
                                        policy_url
                                    );
                                }
                            }
                            Err(e) => eprintln!("[policy-server] failed to read body: {e}"),
                        }
                    }
                    Err(e) => eprintln!("[policy-server] fetch error: {e}"),
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
        tokio::spawn(async move {
            mcp_gateway::run_mcp_gateway(
                mcp_port,
                mcp_upstream,
                active_policy,
                registry_clone,
                audit_clone,
                telemetry_clone,
                secret_clone,
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
                let secret_file = args.secret_file.clone();
                let nonce_clone = Arc::clone(&nonce_store);
                tokio::spawn(async move {
                    handle_client_connection(
                        stream,
                        policy_snapshot,
                        registry_clone,
                        logger_clone,
                        telemetry_clone,
                        secret_file,
                        nonce_clone,
                    )
                    .await;
                });
            }
            Err(err) => println!("Worker interface connection drop error: {}", err),
        }
    }
}
