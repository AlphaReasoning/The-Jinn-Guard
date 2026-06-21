use anyhow::{anyhow, Result};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientProposal {
    #[serde(default)]
    pub session_privilege_bit: Option<f64>,
    #[serde(default)]
    pub action_risk_score: Option<f64>,
    pub sequence_counter: u64,
    #[serde(default)]
    pub intent_name: Option<String>,
    #[serde(default)]
    pub prompt: Option<String>,
    #[serde(default)]
    pub plan: Option<String>,
    #[serde(default)]
    pub source_code: Option<String>,
    #[serde(default)]
    pub requested_capabilities: Vec<String>,
    #[serde(default)]
    pub proposed_action: Option<ProposedAction>,
    /// Caller-supplied runtime telemetry variables fed into Z3 invariant checking.
    /// Example: {"spending_ceiling_usd": 75.0, "privilege_escalation_depth": 1.0}
    #[serde(default)]
    pub context_vars: HashMap<String, f64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProposedAction {
    ShellCommand { command: String },
    FileWrite { path: String, contents: String },
    NetworkRequest { method: String, url: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservationRecord {
    pub pid: u32,
    pub start_time: u64,
    pub uid: u32,
    pub gid: u32,
    pub executable_path: Option<String>,
    pub command_line: Vec<String>,
    pub namespace_observed: bool,
    pub namespace_pid_inode: Option<u64>,
    pub namespace_net_inode: Option<u64>,
    pub socket_peer_verified: bool,
    pub observed_at_unix_secs: u64,
}

pub fn get_process_start_time(pid: u32) -> Option<u64> {
    let stat_path = format!("/proc/{pid}/stat");
    let content = fs::read_to_string(stat_path).ok()?;
    let last_rparen = content.rfind(')')?;
    let post_expr = &content[last_rparen + 1..];
    let parts: Vec<&str> = post_expr.split_whitespace().collect();
    if parts.len() > 19 {
        parts[19].parse::<u64>().ok()
    } else {
        None
    }
}

pub fn get_namespace_inode(pid: u32, ns_type: &str) -> Option<u64> {
    let path = format!("/proc/{pid}/ns/{ns_type}");
    fs::metadata(path).map(|m| m.ino()).ok()
}

impl ObservationRecord {
    pub fn from_peer(pid: u32, uid: u32, gid: u32) -> Self {
        let proc_root = PathBuf::from(format!("/proc/{pid}"));
        let executable_path = fs::read_link(proc_root.join("exe"))
            .ok()
            .and_then(|path| path.into_os_string().into_string().ok());
        let command_line = fs::read(proc_root.join("cmdline"))
            .map(|bytes| {
                bytes
                    .split(|byte| *byte == 0)
                    .filter(|part| !part.is_empty())
                    .filter_map(|part| String::from_utf8(part.to_vec()).ok())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let namespace_observed = proc_root.join("ns/pid").exists();
        let namespace_pid_inode = get_namespace_inode(pid, "pid");
        let namespace_net_inode = get_namespace_inode(pid, "net");
        let start_time = get_process_start_time(pid).unwrap_or(0);

        Self {
            pid,
            start_time,
            uid,
            gid,
            executable_path,
            command_line,
            namespace_observed,
            namespace_pid_inode,
            namespace_net_inode,
            socket_peer_verified: true,
            observed_at_unix_secs: now_unix_secs(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityProfile {
    pub uid: u32,
    pub gid: u32,
    pub is_root: bool,
    pub has_process_identity: bool,
    pub namespace_observed: bool,
    pub namespace_pid_inode: Option<u64>,
    pub namespace_net_inode: Option<u64>,
    pub requested_capabilities: Vec<String>,
}

impl CapabilityProfile {
    pub fn from_observation(
        observation: &ObservationRecord,
        requested_capabilities: &[String],
    ) -> Self {
        Self {
            uid: observation.uid,
            gid: observation.gid,
            is_root: observation.uid == 0,
            has_process_identity: observation.executable_path.is_some(),
            namespace_observed: observation.namespace_observed,
            namespace_pid_inode: observation.namespace_pid_inode,
            namespace_net_inode: observation.namespace_net_inode,
            requested_capabilities: requested_capabilities.to_vec(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IntentClass {
    ReadOnly,
    FileWrite,
    NetworkAccess,
    ProcessExecution,
    PrivilegeChange,
    SourceModification,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticIntent {
    pub class: IntentClass,
    pub confidence: f64,
    pub risk_score: f64,
    pub signals: Vec<String>,
}

pub trait SemanticAnalysisService {
    fn classify(&self, proposal: &ClientProposal) -> SemanticIntent;
}

pub struct LocalHeuristicSemanticService;

impl SemanticAnalysisService for LocalHeuristicSemanticService {
    fn classify(&self, proposal: &ClientProposal) -> SemanticIntent {
        let mut text = String::new();
        append_field(&mut text, proposal.intent_name.as_deref());
        append_field(&mut text, proposal.prompt.as_deref());
        append_field(&mut text, proposal.plan.as_deref());
        append_field(&mut text, proposal.source_code.as_deref());
        for capability in &proposal.requested_capabilities {
            append_field(&mut text, Some(capability));
        }

        let text = text.to_ascii_lowercase();
        let mut signals = Vec::new();
        let mut class = IntentClass::Unknown;
        let mut score = 35.0;

        if contains_any(
            &text,
            &["sudo", "setuid", "chmod +s", "capset", "privilege"],
        ) {
            class = IntentClass::PrivilegeChange;
            score = 90.0;
            signals.push("privilege_transition".to_string());
        } else if contains_any(
            &text,
            &["exec", "spawn", "shell", "bash", "subprocess", "command"],
        ) {
            class = IntentClass::ProcessExecution;
            score = 80.0;
            signals.push("process_execution".to_string());
        } else if contains_any(
            &text,
            &["delete", "overwrite", "write file", "rm -", "unlink"],
        ) {
            class = IntentClass::FileWrite;
            score = 70.0;
            signals.push("filesystem_mutation".to_string());
        } else if contains_any(
            &text,
            &["connect", "socket", "http", "https", "network", "exfil"],
        ) {
            class = IntentClass::NetworkAccess;
            score = 65.0;
            signals.push("network_access".to_string());
        } else if contains_any(&text, &["patch", "source", "compile", "cargo", "python"]) {
            class = IntentClass::SourceModification;
            score = 55.0;
            signals.push("source_or_build_action".to_string());
        } else if contains_any(&text, &["read", "inspect", "summarize", "list"]) {
            class = IntentClass::ReadOnly;
            score = 20.0;
            signals.push("read_only".to_string());
        }

        if proposal
            .source_code
            .as_ref()
            .is_some_and(|source| !source.trim().is_empty())
        {
            score = f64::max(score, 55.0);
            if !signals.iter().any(|signal| signal == "source_present") {
                signals.push("source_present".to_string());
            }
        }

        SemanticIntent {
            class,
            confidence: if text.trim().is_empty() { 0.10 } else { 0.65 },
            risk_score: clamp_score(score),
            signals,
        }
    }
}

pub struct CombinedSemanticService {
    pub rootai_socket_path: Option<String>,
    /// Counts fallback-to-heuristic events since daemon start (for telemetry).
    pub fallback_count: Arc<std::sync::atomic::AtomicU64>,
}

/// Wire request sent to the RootAI socket service.
#[derive(Serialize)]
struct RootAiRequest<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    prompt: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    intent_name: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    plan: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_code: Option<&'a str>,
}

/// Wire response received from the RootAI socket service.
#[derive(Deserialize)]
struct RootAiResponse {
    intent_class: String,
    risk_score: f64,
    confidence: f64,
}

impl RootAiResponse {
    fn to_intent_class(&self) -> IntentClass {
        match self.intent_class.as_str() {
            "benign" | "read_only" => IntentClass::ReadOnly,
            "semantic_manipulation" | "source_modification" => IntentClass::SourceModification,
            "privilege_escalation" | "privilege_change" => IntentClass::PrivilegeChange,
            "data_exfiltration" | "network_access" => IntentClass::NetworkAccess,
            "system_compromise" | "process_execution" => IntentClass::ProcessExecution,
            "file_write" => IntentClass::FileWrite,
            _ => IntentClass::Unknown,
        }
    }
}

impl SemanticAnalysisService for CombinedSemanticService {
    fn classify(&self, proposal: &ClientProposal) -> SemanticIntent {
        if let Some(ref socket_path) = self.rootai_socket_path {
            match self.query_rootai(socket_path, proposal) {
                Ok(intent) => return intent,
                Err(_) => {
                    // Silent fallback — increment telemetry counter only.
                    self.fallback_count
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            }
        }
        LocalHeuristicSemanticService.classify(proposal)
    }
}

impl CombinedSemanticService {
    /// Perform a quick connect-only probe to check whether the RootAI service
    /// is currently reachable.  Does not send any data.
    pub fn rootai_available(&self) -> bool {
        use std::os::unix::net::UnixStream;
        use std::time::Duration;
        if let Some(ref path) = self.rootai_socket_path {
            match UnixStream::connect(path) {
                Ok(stream) => {
                    // Set a tight timeout then drop immediately.
                    let _ = stream.set_read_timeout(Some(Duration::from_millis(80)));
                    true
                }
                Err(_) => false,
            }
        } else {
            false
        }
    }

    /// Internal: open UDS connection to RootAI with 80 ms timeout, send a
    /// length-prefixed JSON request, read a length-prefixed JSON response.
    fn query_rootai(&self, socket_path: &str, proposal: &ClientProposal) -> Result<SemanticIntent> {
        use std::io::{Read, Write};
        use std::os::unix::net::UnixStream;
        use std::time::Duration;

        let timeout = Some(Duration::from_millis(80));

        let mut stream =
            UnixStream::connect(socket_path).map_err(|e| anyhow!("RootAI connect: {}", e))?;
        stream
            .set_read_timeout(timeout)
            .map_err(|e| anyhow!("RootAI read_timeout: {}", e))?;
        stream
            .set_write_timeout(timeout)
            .map_err(|e| anyhow!("RootAI write_timeout: {}", e))?;

        // Build and serialise the request payload.
        let req = RootAiRequest {
            prompt: proposal.prompt.as_deref(),
            intent_name: proposal.intent_name.as_deref(),
            plan: proposal.plan.as_deref(),
            source_code: proposal.source_code.as_deref(),
        };
        let req_bytes = serde_json::to_vec(&req).map_err(|e| anyhow!("RootAI serialize: {}", e))?;

        // Length-prefixed write: 4-byte big-endian u32 then JSON bytes.
        let len_u32 = req_bytes.len() as u32;
        stream
            .write_all(&len_u32.to_be_bytes())
            .map_err(|e| anyhow!("RootAI len write: {}", e))?;
        stream
            .write_all(&req_bytes)
            .map_err(|e| anyhow!("RootAI body write: {}", e))?;
        stream.flush().map_err(|e| anyhow!("RootAI flush: {}", e))?;

        // Length-prefixed read: 4-byte big-endian u32 then JSON bytes.
        let mut len_buf = [0u8; 4];
        stream
            .read_exact(&mut len_buf)
            .map_err(|e| anyhow!("RootAI resp len read: {}", e))?;
        let resp_len = u32::from_be_bytes(len_buf) as usize;
        if resp_len > 65_536 {
            return Err(anyhow!("RootAI response too large: {} bytes", resp_len));
        }
        let mut resp_buf = vec![0u8; resp_len];
        stream
            .read_exact(&mut resp_buf)
            .map_err(|e| anyhow!("RootAI resp body read: {}", e))?;

        let resp: RootAiResponse =
            serde_json::from_slice(&resp_buf).map_err(|e| anyhow!("RootAI deserialize: {}", e))?;

        // Only trust the response when confidence is high enough.
        if resp.confidence < 0.7 {
            return Err(anyhow!("RootAI confidence too low: {:.3}", resp.confidence));
        }

        let class = resp.to_intent_class();
        let risk_score = resp.risk_score.clamp(0.0, 100.0);

        Ok(SemanticIntent {
            class,
            confidence: resp.confidence,
            risk_score,
            signals: vec!["rootai_classified".to_string()],
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessment {
    pub observed_risk: f64,
    pub semantic_risk: f64,
    pub topology_risk: f64,
    pub declared_risk: Option<f64>,
    pub fused_risk: f64,
    pub trust_score: f64,
    pub reasons: Vec<String>,
}

impl RiskAssessment {
    pub fn assess(
        observation: &ObservationRecord,
        semantic_intent: &SemanticIntent,
        capability_profile: &CapabilityProfile,
        declared_risk: Option<f64>,
    ) -> Self {
        let mut observed_risk = 0.0;
        let mut reasons = Vec::new();

        if !observation.socket_peer_verified {
            observed_risk += 40.0;
            reasons.push("socket_peer_unverified".to_string());
        }
        if capability_profile.is_root {
            observed_risk += 25.0;
            reasons.push("root_uid".to_string());
        }
        if !capability_profile.has_process_identity {
            observed_risk += 20.0;
            reasons.push("missing_executable_identity".to_string());
        }
        if !capability_profile.namespace_observed {
            observed_risk += 10.0;
            reasons.push("missing_namespace_observation".to_string());
        }

        let mut topology_risk = 0.0;
        for capability in &capability_profile.requested_capabilities {
            let capability = capability.to_ascii_lowercase();
            if contains_any(&capability, &["network", "connect", "socket"]) {
                topology_risk += 15.0;
                reasons.push("requested_network_capability".to_string());
            }
            if contains_any(&capability, &["write", "filesystem", "file"]) {
                topology_risk += 12.0;
                reasons.push("requested_filesystem_capability".to_string());
            }
            if contains_any(&capability, &["exec", "process", "shell"]) {
                topology_risk += 18.0;
                reasons.push("requested_process_capability".to_string());
            }
        }

        let observed_risk = clamp_score(observed_risk);
        let topology_risk = clamp_score(topology_risk);
        let semantic_risk = clamp_score(semantic_intent.risk_score);
        let declared_risk = declared_risk.map(clamp_score);

        let weighted = (semantic_risk * 0.55) + (observed_risk * 0.30) + (topology_risk * 0.15);
        let mut fused_risk = f64::max(weighted, semantic_risk);
        fused_risk = f64::max(fused_risk, observed_risk);

        if let Some(declared) = declared_risk {
            if declared > fused_risk {
                reasons.push("client_declared_risk_raised_score".to_string());
                fused_risk = declared;
            } else {
                reasons.push("client_declared_risk_not_authoritative".to_string());
            }
        } else {
            reasons.push("client_declared_risk_absent".to_string());
        }

        let fused_risk = clamp_score(fused_risk);
        let trust_score = clamp_score(100.0 - fused_risk);

        Self {
            observed_risk,
            semantic_risk,
            topology_risk,
            declared_risk,
            fused_risk,
            trust_score,
            reasons,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyVerdict {
    Allow,
    /// Execution is permitted subject to the ConstraintSet restrictions.
    Constrain,
    Deny,
}

/// Restrictions applied when the verdict is `Constrain`.
/// The daemon enforces these before executing and encodes them in the response
/// so the Python SDK (and MCP gateway) can apply them client-side too.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ConstraintSet {
    /// Strip any PII or secrets from the action output before returning it.
    pub redact_output: bool,
    /// Maximum calls per second this agent is allowed. `None` = unlimited.
    pub rate_limit_rps: Option<u32>,
    /// If set, network requests must target one of these hostnames/IPs.
    /// Empty vec = allow any (constraint disabled).
    pub allowed_network_destinations: Vec<String>,
    /// Cap the number of tokens/bytes in ShellCommand output.
    pub output_byte_limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub verdict: PolicyVerdict,
    pub reason: String,
    pub risk_score: f64,
    pub trust_score: f64,
    /// Populated when verdict == Constrain.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub constraints: Option<ConstraintSet>,
}

impl PolicyDecision {
    pub fn allow(assessment: &RiskAssessment) -> Self {
        Self {
            verdict: PolicyVerdict::Allow,
            reason: "risk_within_policy".to_string(),
            risk_score: assessment.fused_risk,
            trust_score: assessment.trust_score,
            constraints: None,
        }
    }

    pub fn deny(reason: impl Into<String>, assessment: &RiskAssessment) -> Self {
        Self {
            verdict: PolicyVerdict::Deny,
            reason: reason.into(),
            risk_score: assessment.fused_risk,
            trust_score: assessment.trust_score,
            constraints: None,
        }
    }

    /// Produce a CONSTRAIN decision for mid-band risk (between allow and deny).
    /// The caller supplies the constraint set appropriate for the risk level.
    pub fn constrain(
        reason: impl Into<String>,
        assessment: &RiskAssessment,
        constraints: ConstraintSet,
    ) -> Self {
        Self {
            verdict: PolicyVerdict::Constrain,
            reason: reason.into(),
            risk_score: assessment.fused_risk,
            trust_score: assessment.trust_score,
            constraints: Some(constraints),
        }
    }

    pub fn is_allow(&self) -> bool {
        self.verdict == PolicyVerdict::Allow
    }

    pub fn is_constrain(&self) -> bool {
        self.verdict == PolicyVerdict::Constrain
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionRequest {
    pub action: ProposedAction,
    pub observation: ObservationRecord,
    pub semantic_intent: SemanticIntent,
    pub risk_assessment: RiskAssessment,
    pub policy_decision: PolicyDecision,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionDecision {
    pub permitted: bool,
    /// True when the action is permitted but subject to constraints.
    pub constrained: bool,
    pub reason: String,
    pub action: ProposedAction,
    pub policy_decision: PolicyDecision,
    /// Populated when constrained == true.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_constraints: Option<ConstraintSet>,
}

pub struct ExecutionBroker;

/// Phase 4 — Enforcement denylist and allowlists.
mod broker_policy {
    /// Shell commands that are unconditionally denied regardless of risk score.
    pub const DENIED_COMMANDS: &[&str] = &[
        "rm -rf",
        "dd if=",
        "mkfs",
        "chmod 777",
        "chmod +s",
        "sudo su",
        "su -",
        "passwd",
        "chsh",
        "visudo",
        "curl | sh",
        "wget -O- |",
        "bash -i",
        "nc -e",
        "ncat -e",
        "iptables -F",
        "ufw disable",
        "systemctl stop",
    ];

    /// Only these URL scheme+host prefixes are permitted for network requests.
    pub const ALLOWED_URL_PREFIXES: &[&str] = &["https://"];

    /// URL patterns that are explicitly denied even under https.
    pub const DENIED_URL_PATTERNS: &[&str] = &[
        "169.254.", // AWS/GCP instance metadata
        "::1",
        "localhost",
        "127.0.0.",
        "0.0.0.0",
    ];

    /// Path prefixes that agents may NOT write to.
    pub const DENIED_PATH_PREFIXES: &[&str] = &[
        "/etc/",
        "/proc/",
        "/sys/",
        "/dev/",
        "/boot/",
        "/run/jinnguard/",
        "/var/log/jinnguard/",
    ];
}

impl ExecutionBroker {
    pub fn decide(&self, request: ExecutionRequest) -> ExecutionDecision {
        // Hard enforcement checks run first (denylist / path traversal).
        if let Some(deny_reason) = self.enforce(&request) {
            return ExecutionDecision {
                permitted: false,
                constrained: false,
                reason: deny_reason,
                action: request.action,
                policy_decision: request.policy_decision,
                active_constraints: None,
            };
        }

        // ── Item 3: CONSTRAIN path ───────────────────────────────────────────
        if request.policy_decision.is_constrain() {
            let constraints = request
                .policy_decision
                .constraints
                .clone()
                .unwrap_or_default();

            // Enforce network destination filter for constrained network requests.
            if let ProposedAction::NetworkRequest { ref url, .. } = request.action {
                if !constraints.allowed_network_destinations.is_empty() {
                    let url_lower = url.to_lowercase();
                    let allowed = constraints
                        .allowed_network_destinations
                        .iter()
                        .any(|dest| url_lower.contains(&dest.to_lowercase()));
                    if !allowed {
                        return ExecutionDecision {
                            permitted: false,
                            constrained: true,
                            reason: format!("CONSTRAINT_NETWORK_DESTINATION_NOT_ALLOWED:{}", url),
                            action: request.action,
                            policy_decision: request.policy_decision,
                            active_constraints: Some(constraints),
                        };
                    }
                }
            }

            return ExecutionDecision {
                permitted: true,
                constrained: true,
                reason: format!("constrained:{}", request.policy_decision.reason),
                active_constraints: Some(constraints),
                action: request.action,
                policy_decision: request.policy_decision,
            };
        }
        // ── end CONSTRAIN ────────────────────────────────────────────────────

        let permitted = request.policy_decision.is_allow();
        ExecutionDecision {
            permitted,
            constrained: false,
            reason: if permitted {
                "policy_cleared".to_string()
            } else {
                format!("policy_denied:{}", request.policy_decision.reason)
            },
            action: request.action,
            policy_decision: request.policy_decision,
            active_constraints: None,
        }
    }

    /// Returns `Some(deny_reason)` when the action violates a hard enforcement rule.
    fn enforce(&self, request: &ExecutionRequest) -> Option<String> {
        match &request.action {
            ProposedAction::ShellCommand { command } => {
                let cmd_lower = command.to_ascii_lowercase();
                for denied in broker_policy::DENIED_COMMANDS {
                    if cmd_lower.contains(denied) {
                        return Some(format!("BROKER_DENY_COMMAND_DENYLIST:{}", denied));
                    }
                }
                None
            }
            ProposedAction::NetworkRequest { method: _, url } => {
                // Must start with an allowed prefix.
                let allowed = broker_policy::ALLOWED_URL_PREFIXES
                    .iter()
                    .any(|prefix| url.starts_with(prefix));
                if !allowed {
                    return Some(format!("BROKER_DENY_URL_SCHEME_NOT_ALLOWED:{}", url));
                }
                // Must not match a denied pattern.
                for pattern in broker_policy::DENIED_URL_PATTERNS {
                    if url.contains(pattern) {
                        return Some(format!("BROKER_DENY_URL_PATTERN_MATCHED:{}", pattern));
                    }
                }
                None
            }
            ProposedAction::FileWrite { path, contents: _ } => {
                for prefix in broker_policy::DENIED_PATH_PREFIXES {
                    if path.starts_with(prefix) {
                        return Some(format!("BROKER_DENY_PATH_PREFIX_RESTRICTED:{}", prefix));
                    }
                }
                // Block directory traversal attempts.
                if path.contains("../") || path.contains("/./") {
                    return Some("BROKER_DENY_PATH_TRAVERSAL_DETECTED".to_string());
                }
                None
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentLineage {
    pub pid: u32,
    pub start_time: u64,
    pub uid: u32,
    pub gid: u32,
    pub executable_path: Option<String>,
    pub first_seen_unix_secs: u64,
    pub last_seen_unix_secs: u64,
    pub first_sequence: u64,
    pub last_sequence: u64,
    pub max_assessed_risk: f64,
    pub decisions_seen: u64,
}

impl AgentLineage {
    pub fn new(
        observation: &ObservationRecord,
        sequence: u64,
        assessment: &RiskAssessment,
    ) -> Self {
        Self {
            pid: observation.pid,
            start_time: observation.start_time,
            uid: observation.uid,
            gid: observation.gid,
            executable_path: observation.executable_path.clone(),
            first_seen_unix_secs: observation.observed_at_unix_secs,
            last_seen_unix_secs: observation.observed_at_unix_secs,
            first_sequence: sequence,
            last_sequence: 0,
            max_assessed_risk: assessment.fused_risk,
            decisions_seen: 0,
        }
    }

    pub fn validate_sequence(&self, sequence: u64) -> Result<()> {
        if sequence == 0 {
            return Err(anyhow!("sequence_counter_zero"));
        }
        if self.last_sequence != 0 && sequence <= self.last_sequence {
            return Err(anyhow!("sequence_replay"));
        }
        Ok(())
    }

    pub fn records_behavioral_drift(&self, assessment: &RiskAssessment) -> bool {
        self.decisions_seen > 0 && assessment.fused_risk > self.max_assessed_risk + 25.0
    }

    pub fn record(
        &mut self,
        observation: &ObservationRecord,
        sequence: u64,
        assessment: &RiskAssessment,
    ) {
        self.last_seen_unix_secs = observation.observed_at_unix_secs;
        self.last_sequence = sequence;
        self.max_assessed_risk = f64::max(self.max_assessed_risk, assessment.fused_risk);
        self.decisions_seen += 1;
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct RegistryData {
    pub lineages: HashMap<String, AgentLineage>,
}

pub struct LineageRegistry {
    db: Arc<Mutex<rusqlite::Connection>>,
    /// Legacy JSON path supplied by the caller (kept for backward-compat probing).
    #[allow(dead_code)]
    file_path: String,
    pub data: RegistryData,
}

/// Compute the SQLite DB path from the caller-supplied path.
/// If the path ends in `.json`, use `<stem>.db` alongside it.
/// Otherwise use `<path>.db`.
fn lineage_db_path(file_path: &str) -> String {
    match file_path.strip_suffix(".json") {
        Some(stem) => format!("{stem}.db"),
        None => format!("{file_path}.db"),
    }
}

impl LineageRegistry {
    pub fn load_or_create(file_path: &str) -> Self {
        let db_path = lineage_db_path(file_path);
        let conn = rusqlite::Connection::open(&db_path)
            .expect("LineageRegistry: failed to open SQLite DB");

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS lineages (
                key               TEXT PRIMARY KEY,
                pid               INTEGER,
                uid               INTEGER,
                gid               INTEGER,
                start_time        INTEGER,
                first_seen        INTEGER,
                last_seen         INTEGER,
                first_sequence    INTEGER,
                last_sequence     INTEGER,
                max_assessed_risk REAL,
                decisions_seen    INTEGER,
                executable_path   TEXT
            );",
        )
        .expect("LineageRegistry: failed to create table");

        // Attempt to migrate from a legacy JSON file if it still exists.
        let mut data = RegistryData {
            lineages: HashMap::new(),
        };
        if Path::new(file_path).exists() && file_path.ends_with(".json") {
            if let Ok(content) = fs::read_to_string(file_path) {
                if let Ok(legacy) = serde_json::from_str::<RegistryData>(&content) {
                    data = legacy;
                    // Persist migrated data into SQLite immediately.
                    for (key, lineage) in &data.lineages {
                        let _ = conn.execute(
                            "INSERT OR REPLACE INTO lineages \
                             (key, pid, uid, gid, start_time, first_seen, last_seen, \
                              first_sequence, last_sequence, max_assessed_risk, \
                              decisions_seen, executable_path) \
                             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
                            params![
                                key,
                                lineage.pid as i64,
                                lineage.uid as i64,
                                lineage.gid as i64,
                                lineage.start_time as i64,
                                lineage.first_seen_unix_secs as i64,
                                lineage.last_seen_unix_secs as i64,
                                lineage.first_sequence as i64,
                                lineage.last_sequence as i64,
                                lineage.max_assessed_risk,
                                lineage.decisions_seen as i64,
                                lineage.executable_path.as_deref(),
                            ],
                        );
                    }
                    // Remove the old JSON file after successful migration.
                    let _ = fs::remove_file(file_path);
                }
            }
        }

        // Load all rows from DB into the in-memory HashMap.
        {
            let mut stmt = conn
                .prepare(
                    "SELECT key, pid, uid, gid, start_time, first_seen, last_seen, \
                     first_sequence, last_sequence, max_assessed_risk, \
                     decisions_seen, executable_path FROM lineages",
                )
                .expect("LineageRegistry: failed to prepare SELECT");
            let rows = stmt
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        AgentLineage {
                            pid: row.get::<_, i64>(1)? as u32,
                            uid: row.get::<_, i64>(2)? as u32,
                            gid: row.get::<_, i64>(3)? as u32,
                            start_time: row.get::<_, i64>(4)? as u64,
                            first_seen_unix_secs: row.get::<_, i64>(5)? as u64,
                            last_seen_unix_secs: row.get::<_, i64>(6)? as u64,
                            first_sequence: row.get::<_, i64>(7)? as u64,
                            last_sequence: row.get::<_, i64>(8)? as u64,
                            max_assessed_risk: row.get::<_, f64>(9)?,
                            decisions_seen: row.get::<_, i64>(10)? as u64,
                            executable_path: row.get::<_, Option<String>>(11)?,
                        },
                    ))
                })
                .expect("LineageRegistry: failed to query rows");
            for row in rows.flatten() {
                data.lineages.insert(row.0, row.1);
            }
        }

        Self {
            db: Arc::new(Mutex::new(conn)),
            file_path: file_path.to_string(),
            data,
        }
    }

    pub fn save(&self) -> Result<()> {
        let conn = self
            .db
            .lock()
            .map_err(|_| anyhow!("LineageRegistry: mutex poisoned"))?;
        for (key, lineage) in &self.data.lineages {
            conn.execute(
                "INSERT OR REPLACE INTO lineages \
                 (key, pid, uid, gid, start_time, first_seen, last_seen, \
                  first_sequence, last_sequence, max_assessed_risk, \
                  decisions_seen, executable_path) \
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
                params![
                    key,
                    lineage.pid as i64,
                    lineage.uid as i64,
                    lineage.gid as i64,
                    lineage.start_time as i64,
                    lineage.first_seen_unix_secs as i64,
                    lineage.last_seen_unix_secs as i64,
                    lineage.first_sequence as i64,
                    lineage.last_sequence as i64,
                    lineage.max_assessed_risk,
                    lineage.decisions_seen as i64,
                    lineage.executable_path.as_deref(),
                ],
            )?;
        }
        Ok(())
    }

    pub fn prune_dead_processes(&mut self) {
        let mut pruned_keys: Vec<String> = Vec::new();
        self.data.lineages.retain(|key, lineage| {
            let proc_path = format!("/proc/{}", lineage.pid);
            if !Path::new(&proc_path).exists() {
                pruned_keys.push(key.clone());
                return false;
            }
            if let Some(curr_start) = get_process_start_time(lineage.pid) {
                if curr_start != lineage.start_time {
                    pruned_keys.push(key.clone());
                    return false;
                }
                true
            } else {
                pruned_keys.push(key.clone());
                false
            }
        });
        // Delete pruned rows from the DB (best-effort, no panic on error).
        if !pruned_keys.is_empty() {
            if let Ok(conn) = self.db.lock() {
                for key in &pruned_keys {
                    let _ = conn.execute("DELETE FROM lineages WHERE key = ?1", params![key]);
                }
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub index: u64,
    pub timestamp_secs: u64,
    pub prev_hash: String,
    pub observation: ObservationRecord,
    pub intent: SemanticIntent,
    pub assessment: RiskAssessment,
    pub decision: PolicyDecision,
    pub hash: String,
}

impl AuditEntry {
    pub fn calculate_hash(
        index: u64,
        timestamp_secs: u64,
        prev_hash: &str,
        observation: &ObservationRecord,
        intent: &SemanticIntent,
        assessment: &RiskAssessment,
        decision: &PolicyDecision,
    ) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(index.to_be_bytes());
        hasher.update(timestamp_secs.to_be_bytes());
        hasher.update(prev_hash.as_bytes());

        let obs_json = serde_json::to_string(observation).unwrap_or_default();
        let intent_json = serde_json::to_string(intent).unwrap_or_default();
        let assess_json = serde_json::to_string(assessment).unwrap_or_default();
        let dec_json = serde_json::to_string(decision).unwrap_or_default();

        hasher.update(obs_json.as_bytes());
        hasher.update(intent_json.as_bytes());
        hasher.update(assess_json.as_bytes());
        hasher.update(dec_json.as_bytes());

        hex::encode(hasher.finalize())
    }
}

pub struct AuditLogger {
    /// JSONL file path (kept for backward-compat and the tamper-evident hash chain).
    file_path: String,
    /// SQLite connection for structured queryable storage.
    db: Arc<Mutex<rusqlite::Connection>>,
    /// Serializes the whole append (read-last-index → hash → JSONL → SQLite).
    /// Without this, two concurrent governed decisions can both read the same
    /// last index and produce duplicate audit indices / a broken hash chain.
    write_guard: Mutex<()>,
}

impl AuditLogger {
    pub fn new(file_path: &str) -> Self {
        // Derive the DB path alongside the JSONL file.
        let db_path = format!("{}.db", file_path);
        let conn =
            rusqlite::Connection::open(&db_path).expect("AuditLogger: failed to open SQLite DB");
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS audit_log (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                idx            INTEGER,
                timestamp_secs INTEGER,
                prev_hash      TEXT,
                pid            INTEGER,
                uid            INTEGER,
                intent_class   TEXT,
                fused_risk     REAL,
                trust_score    REAL,
                verdict        TEXT,
                reason         TEXT,
                entry_hash     TEXT,
                full_json      TEXT
            );",
        )
        .expect("AuditLogger: failed to create audit_log table");
        Self {
            file_path: file_path.to_string(),
            db: Arc::new(Mutex::new(conn)),
            write_guard: Mutex::new(()),
        }
    }

    pub fn log(
        &self,
        observation: &ObservationRecord,
        intent: &SemanticIntent,
        assessment: &RiskAssessment,
        decision: &PolicyDecision,
    ) -> Result<()> {
        // Serialize the entire append. The index read + hash + JSONL write +
        // SQLite insert must be atomic, or concurrent decisions can share an
        // index and corrupt the tamper-evident chain.
        let _write_guard = self
            .write_guard
            .lock()
            .map_err(|_| anyhow!("AuditLogger: write mutex poisoned"))?;
        let (next_index, prev_hash) = self.get_last_entry_info()?;
        let now = now_unix_secs();
        let current_hash = AuditEntry::calculate_hash(
            next_index,
            now,
            &prev_hash,
            observation,
            intent,
            assessment,
            decision,
        );

        let entry = AuditEntry {
            index: next_index,
            timestamp_secs: now,
            prev_hash,
            observation: observation.clone(),
            intent: intent.clone(),
            assessment: assessment.clone(),
            decision: decision.clone(),
            hash: current_hash.clone(),
        };

        // ── 1. Append to the JSONL file (tamper-evident chain; tests read this) ──
        let serialized = serde_json::to_string(&entry)? + "\n";
        {
            use std::io::Write;
            let mut file = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.file_path)?;
            file.write_all(serialized.as_bytes())?;
        }

        // ── 2. Insert into SQLite for structured querying ──
        let full_json = serde_json::to_string(&entry)?;
        let intent_class_str = format!("{:?}", entry.intent.class);
        let verdict_str = format!("{:?}", entry.decision.verdict);
        if let Ok(conn) = self.db.lock() {
            let _ = conn.execute(
                "INSERT INTO audit_log \
                 (idx, timestamp_secs, prev_hash, pid, uid, intent_class, \
                  fused_risk, trust_score, verdict, reason, entry_hash, full_json) \
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
                params![
                    entry.index as i64,
                    entry.timestamp_secs as i64,
                    &entry.prev_hash,
                    entry.observation.pid as i64,
                    entry.observation.uid as i64,
                    &intent_class_str,
                    entry.assessment.fused_risk,
                    entry.assessment.trust_score,
                    &verdict_str,
                    &entry.decision.reason,
                    &current_hash,
                    &full_json,
                ],
            );
        }

        Ok(())
    }

    /// Return the last N audit entries deserialized from `full_json` in the DB.
    pub fn query_recent(&self, limit: u64) -> Result<Vec<AuditEntry>> {
        let conn = self
            .db
            .lock()
            .map_err(|_| anyhow!("AuditLogger: mutex poisoned"))?;
        let mut stmt = conn.prepare("SELECT full_json FROM audit_log ORDER BY id DESC LIMIT ?1")?;
        let rows = stmt.query_map(params![limit as i64], |row| row.get::<_, String>(0))?;
        let mut entries = Vec::new();
        for row in rows {
            let json = row?;
            if let Ok(entry) = serde_json::from_str::<AuditEntry>(&json) {
                entries.push(entry);
            }
        }
        // Reverse so entries are in chronological order (oldest first).
        entries.reverse();
        Ok(entries)
    }

    fn get_last_entry_info(&self) -> Result<(u64, String)> {
        // Primary: query the SQLite DB for the last row.
        if let Ok(conn) = self.db.lock() {
            let result: rusqlite::Result<(i64, String)> = conn.query_row(
                "SELECT idx, entry_hash FROM audit_log ORDER BY id DESC LIMIT 1",
                [],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
            );
            if let Ok((idx, hash)) = result {
                return Ok((idx as u64 + 1, hash));
            }
        }
        // Fallback: scan the JSONL file (covers first-run and migration scenarios).
        if Path::new(&self.file_path).exists() {
            if let Ok(content) = fs::read_to_string(&self.file_path) {
                let lines: Vec<&str> = content.lines().filter(|l| !l.is_empty()).collect();
                if let Some(last_line) = lines.last() {
                    if let Ok(entry) = serde_json::from_str::<AuditEntry>(last_line) {
                        return Ok((entry.index + 1, entry.hash));
                    }
                }
            }
        }
        Ok((0, "0".repeat(64)))
    }
}

pub fn clamp_score(value: f64) -> f64 {
    if !value.is_finite() {
        return 100.0;
    }
    value.clamp(0.0, 100.0)
}

fn append_field(target: &mut String, value: Option<&str>) {
    if let Some(value) = value {
        target.push(' ');
        target.push_str(value);
    }
}

fn contains_any(text: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| text.contains(needle))
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observation() -> ObservationRecord {
        ObservationRecord {
            pid: 42,
            start_time: 12345,
            uid: 1000,
            gid: 1000,
            executable_path: Some("/bin/test-agent".to_string()),
            command_line: vec!["test-agent".to_string()],
            namespace_observed: true,
            namespace_pid_inode: Some(9999),
            namespace_net_inode: Some(8888),
            socket_peer_verified: true,
            observed_at_unix_secs: 1,
        }
    }

    #[test]
    fn declared_low_risk_cannot_lower_semantic_risk() {
        let proposal = ClientProposal {
            session_privilege_bit: Some(0.0),
            action_risk_score: Some(1.0),
            sequence_counter: 1,
            intent_name: Some("run sudo command".to_string()),
            prompt: None,
            plan: None,
            source_code: None,
            requested_capabilities: vec![],
            proposed_action: Some(ProposedAction::ShellCommand {
                command: "id".to_string(),
            }),
            context_vars: std::collections::HashMap::new(),
        };
        let semantic = LocalHeuristicSemanticService.classify(&proposal);
        let capability = CapabilityProfile::from_observation(&observation(), &[]);
        let assessment = RiskAssessment::assess(
            &observation(),
            &semantic,
            &capability,
            proposal.action_risk_score,
        );

        assert!(assessment.fused_risk >= semantic.risk_score);
        assert!(assessment.fused_risk >= 90.0);
    }

    #[test]
    fn declared_high_risk_can_raise_score() {
        let proposal = ClientProposal {
            session_privilege_bit: Some(0.0),
            action_risk_score: Some(88.0),
            sequence_counter: 1,
            intent_name: Some("read plan".to_string()),
            prompt: None,
            plan: None,
            source_code: None,
            requested_capabilities: vec![],
            proposed_action: Some(ProposedAction::ShellCommand {
                command: "id".to_string(),
            }),
            context_vars: std::collections::HashMap::new(),
        };
        let semantic = LocalHeuristicSemanticService.classify(&proposal);
        let capability = CapabilityProfile::from_observation(&observation(), &[]);
        let assessment = RiskAssessment::assess(
            &observation(),
            &semantic,
            &capability,
            proposal.action_risk_score,
        );

        assert_eq!(assessment.fused_risk, 88.0);
    }

    #[test]
    fn execution_broker_permits_only_allowed_policy_decisions() {
        let observation = observation();
        let semantic = SemanticIntent {
            class: IntentClass::ReadOnly,
            confidence: 0.9,
            risk_score: 20.0,
            signals: vec!["read_only".to_string()],
        };
        let capability = CapabilityProfile::from_observation(&observation, &[]);
        let assessment = RiskAssessment::assess(&observation, &semantic, &capability, Some(20.0));
        let policy_decision = PolicyDecision::allow(&assessment);
        let request = ExecutionRequest {
            action: ProposedAction::FileWrite {
                path: "/tmp/mock".to_string(),
                contents: "mock".to_string(),
            },
            observation,
            semantic_intent: semantic,
            risk_assessment: assessment,
            policy_decision,
        };

        let decision = ExecutionBroker.decide(request);
        assert!(decision.permitted);
    }

    #[test]
    fn execution_broker_blocks_denied_policy_decisions() {
        let observation = observation();
        let semantic = SemanticIntent {
            class: IntentClass::NetworkAccess,
            confidence: 0.9,
            risk_score: 90.0,
            signals: vec!["network_access".to_string()],
        };
        let capability = CapabilityProfile::from_observation(&observation, &[]);
        let assessment = RiskAssessment::assess(&observation, &semantic, &capability, Some(90.0));
        let policy_decision = PolicyDecision::deny("risk_ceiling_exceeded", &assessment);
        let request = ExecutionRequest {
            action: ProposedAction::NetworkRequest {
                method: "GET".to_string(),
                url: "https://example.invalid".to_string(),
            },
            observation,
            semantic_intent: semantic,
            risk_assessment: assessment,
            policy_decision,
        };

        let decision = ExecutionBroker.decide(request);
        assert!(!decision.permitted);
    }

    #[test]
    fn test_lineage_registry_saving() {
        let path = "/tmp/test_lineage_reg.json";
        let _ = fs::remove_file(path);
        let mut reg = LineageRegistry::load_or_create(path);
        let obs = observation();
        let semantic = LocalHeuristicSemanticService.classify(&ClientProposal {
            session_privilege_bit: None,
            action_risk_score: None,
            sequence_counter: 1,
            intent_name: None,
            prompt: None,
            plan: None,
            source_code: None,
            requested_capabilities: vec![],
            proposed_action: None,
            context_vars: std::collections::HashMap::new(),
        });
        let capability = CapabilityProfile::from_observation(&obs, &[]);
        let assessment = RiskAssessment::assess(&obs, &semantic, &capability, None);
        let lineage = AgentLineage::new(&obs, 1, &assessment);

        reg.data.lineages.insert("42:12345".to_string(), lineage);
        assert!(reg.save().is_ok());

        let loaded = LineageRegistry::load_or_create(path);
        assert!(loaded.data.lineages.contains_key("42:12345"));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn test_audit_logger_tamper_evident() {
        let path = "/tmp/test_audit_logger_tamper.log";
        let db_path = format!("{path}.db");
        // Clean up any leftover state from previous runs (JSONL + SQLite sidecar).
        let _ = fs::remove_file(path);
        let _ = fs::remove_file(&db_path);
        let logger = AuditLogger::new(path);
        let obs = observation();
        let semantic = SemanticIntent {
            class: IntentClass::ReadOnly,
            confidence: 0.9,
            risk_score: 20.0,
            signals: vec!["read_only".to_string()],
        };
        let capability = CapabilityProfile::from_observation(&obs, &[]);
        let assessment = RiskAssessment::assess(&obs, &semantic, &capability, Some(20.0));
        let decision = PolicyDecision::allow(&assessment);

        assert!(logger.log(&obs, &semantic, &assessment, &decision).is_ok());
        assert!(logger.log(&obs, &semantic, &assessment, &decision).is_ok());

        // Load and check hash chain
        let content = fs::read_to_string(path).unwrap();
        let entries: Vec<AuditEntry> = content
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| serde_json::from_str::<AuditEntry>(l).unwrap())
            .collect();

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].index, 0);
        assert_eq!(entries[1].index, 1);
        assert_eq!(entries[1].prev_hash, entries[0].hash);

        let recalculated = AuditEntry::calculate_hash(
            entries[1].index,
            entries[1].timestamp_secs,
            &entries[1].prev_hash,
            &entries[1].observation,
            &entries[1].intent,
            &entries[1].assessment,
            &entries[1].decision,
        );
        assert_eq!(entries[1].hash, recalculated);

        // Clean up.
        let _ = fs::remove_file(path);
        let _ = fs::remove_file(&db_path);
    }

    #[test]
    fn test_audit_logger_concurrent_indices_unique() {
        // Regression: index read + write must be atomic. Under concurrency, a
        // non-atomic logger produces duplicate indices and a broken chain (caught
        // by the validation suite in a container). Hammer it from many threads
        // and assert the indices are exactly 0..N with no gaps or duplicates.
        let path = "/tmp/test_audit_logger_concurrent.log";
        let db_path = format!("{path}.db");
        let _ = fs::remove_file(path);
        let _ = fs::remove_file(&db_path);

        let logger = std::sync::Arc::new(AuditLogger::new(path));
        let obs = observation();
        let semantic = SemanticIntent {
            class: IntentClass::ReadOnly,
            confidence: 0.9,
            risk_score: 20.0,
            signals: vec!["read_only".to_string()],
        };
        let capability = CapabilityProfile::from_observation(&obs, &[]);
        let assessment = RiskAssessment::assess(&obs, &semantic, &capability, Some(20.0));
        let decision = PolicyDecision::allow(&assessment);

        const THREADS: usize = 8;
        const PER: usize = 40;
        let mut handles = Vec::new();
        for _ in 0..THREADS {
            let l = std::sync::Arc::clone(&logger);
            let (o, s, a, d) = (
                obs.clone(),
                semantic.clone(),
                assessment.clone(),
                decision.clone(),
            );
            handles.push(std::thread::spawn(move || {
                for _ in 0..PER {
                    let _ = l.log(&o, &s, &a, &d);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        let content = fs::read_to_string(path).unwrap();
        let mut indices: Vec<u64> = content
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| serde_json::from_str::<AuditEntry>(l).unwrap().index)
            .collect();
        let total = THREADS * PER;
        assert_eq!(indices.len(), total, "every append must be recorded once");
        indices.sort_unstable();
        let expected: Vec<u64> = (0..total as u64).collect();
        assert_eq!(
            indices, expected,
            "audit indices must be a contiguous 0..N with no duplicates (race-free)"
        );

        let _ = fs::remove_file(path);
        let _ = fs::remove_file(&db_path);
    }

    fn low_risk_observation() -> ObservationRecord {
        ObservationRecord {
            pid: 99,
            start_time: 54321,
            uid: 1001,
            gid: 1001,
            executable_path: Some("/usr/bin/agent".to_string()),
            command_line: vec!["agent".to_string()],
            namespace_observed: true,
            namespace_pid_inode: Some(111),
            namespace_net_inode: Some(222),
            socket_peer_verified: true,
            observed_at_unix_secs: 2,
        }
    }

    fn make_allowed_policy_decision() -> PolicyDecision {
        PolicyDecision {
            constraints: None,
            verdict: PolicyVerdict::Allow,
            reason: "risk_within_policy".to_string(),
            risk_score: 10.0,
            trust_score: 90.0,
        }
    }

    // --- Phase 4: ExecutionBroker enforcement tests ---

    #[test]
    fn broker_blocks_denied_shell_command() {
        let request = ExecutionRequest {
            action: ProposedAction::ShellCommand {
                command: "rm -rf /".to_string(),
            },
            observation: low_risk_observation(),
            semantic_intent: SemanticIntent {
                class: IntentClass::ProcessExecution,
                confidence: 0.9,
                risk_score: 80.0,
                signals: vec![],
            },
            risk_assessment: RiskAssessment {
                observed_risk: 0.0,
                semantic_risk: 80.0,
                topology_risk: 0.0,
                declared_risk: None,
                fused_risk: 80.0,
                trust_score: 20.0,
                reasons: vec![],
            },
            policy_decision: make_allowed_policy_decision(),
        };
        let decision = ExecutionBroker.decide(request);
        assert!(!decision.permitted);
        assert!(decision.reason.contains("BROKER_DENY_COMMAND_DENYLIST"));
    }

    #[test]
    fn broker_blocks_http_url() {
        let request = ExecutionRequest {
            action: ProposedAction::NetworkRequest {
                method: "GET".to_string(),
                url: "http://example.com/data".to_string(),
            },
            observation: low_risk_observation(),
            semantic_intent: SemanticIntent {
                class: IntentClass::NetworkAccess,
                confidence: 0.8,
                risk_score: 30.0,
                signals: vec![],
            },
            risk_assessment: RiskAssessment {
                observed_risk: 0.0,
                semantic_risk: 30.0,
                topology_risk: 0.0,
                declared_risk: None,
                fused_risk: 30.0,
                trust_score: 70.0,
                reasons: vec![],
            },
            policy_decision: make_allowed_policy_decision(),
        };
        let decision = ExecutionBroker.decide(request);
        assert!(!decision.permitted);
        assert!(decision
            .reason
            .contains("BROKER_DENY_URL_SCHEME_NOT_ALLOWED"));
    }

    #[test]
    fn broker_blocks_metadata_url() {
        let request = ExecutionRequest {
            action: ProposedAction::NetworkRequest {
                method: "GET".to_string(),
                url: "https://169.254.169.254/latest/meta-data/".to_string(),
            },
            observation: low_risk_observation(),
            semantic_intent: SemanticIntent {
                class: IntentClass::NetworkAccess,
                confidence: 0.8,
                risk_score: 30.0,
                signals: vec![],
            },
            risk_assessment: RiskAssessment {
                observed_risk: 0.0,
                semantic_risk: 30.0,
                topology_risk: 0.0,
                declared_risk: None,
                fused_risk: 30.0,
                trust_score: 70.0,
                reasons: vec![],
            },
            policy_decision: make_allowed_policy_decision(),
        };
        let decision = ExecutionBroker.decide(request);
        assert!(!decision.permitted);
        assert!(decision.reason.contains("BROKER_DENY_URL_PATTERN_MATCHED"));
    }

    #[test]
    fn broker_blocks_etc_write() {
        let request = ExecutionRequest {
            action: ProposedAction::FileWrite {
                path: "/etc/passwd".to_string(),
                contents: "evil".to_string(),
            },
            observation: low_risk_observation(),
            semantic_intent: SemanticIntent {
                class: IntentClass::FileWrite,
                confidence: 0.9,
                risk_score: 70.0,
                signals: vec![],
            },
            risk_assessment: RiskAssessment {
                observed_risk: 0.0,
                semantic_risk: 70.0,
                topology_risk: 0.0,
                declared_risk: None,
                fused_risk: 70.0,
                trust_score: 30.0,
                reasons: vec![],
            },
            policy_decision: make_allowed_policy_decision(),
        };
        let decision = ExecutionBroker.decide(request);
        assert!(!decision.permitted);
        assert!(decision
            .reason
            .contains("BROKER_DENY_PATH_PREFIX_RESTRICTED"));
    }

    #[test]
    fn broker_blocks_path_traversal() {
        let request = ExecutionRequest {
            action: ProposedAction::FileWrite {
                path: "/home/user/../../../etc/shadow".to_string(),
                contents: "pwned".to_string(),
            },
            observation: low_risk_observation(),
            semantic_intent: SemanticIntent {
                class: IntentClass::FileWrite,
                confidence: 0.9,
                risk_score: 70.0,
                signals: vec![],
            },
            risk_assessment: RiskAssessment {
                observed_risk: 0.0,
                semantic_risk: 70.0,
                topology_risk: 0.0,
                declared_risk: None,
                fused_risk: 70.0,
                trust_score: 30.0,
                reasons: vec![],
            },
            policy_decision: make_allowed_policy_decision(),
        };
        let decision = ExecutionBroker.decide(request);
        assert!(!decision.permitted);
        assert!(decision
            .reason
            .contains("BROKER_DENY_PATH_TRAVERSAL_DETECTED"));
        #[test]
        fn broker_allows_safe_https_request() {
            let request = ExecutionRequest {
                action: ProposedAction::NetworkRequest {
                    method: "GET".to_string(),
                    url: "https://api.openai.com/v1/completions".to_string(),
                },
                observation: low_risk_observation(),
                semantic_intent: SemanticIntent {
                    class: IntentClass::NetworkAccess,
                    confidence: 0.8,
                    risk_score: 30.0,
                    signals: vec!["network_access".to_string()],
                },
                risk_assessment: RiskAssessment {
                    observed_risk: 0.0,
                    semantic_risk: 30.0,
                    topology_risk: 0.0,
                    declared_risk: None,
                    fused_risk: 30.0,
                    trust_score: 70.0,
                    reasons: vec![],
                },
                policy_decision: make_allowed_policy_decision(),
            };
            let decision = ExecutionBroker.decide(request);
            assert!(decision.permitted);
        }
    } // broker_allows_safe_https_request
} // end mod tests

// =============================================================================
// Item 5 — Multi-Agent Delegation Governance
//
// Three sub-systems:
//   A. Trust Decay        — per-agent trust decays over idle time and on denial
//   B. Delegation Chains  — HMAC-signed capability delegation with depth limit
//   C. Swarm Policy       — shared risk budget + active-agent ceiling per swarm
// =============================================================================

// -----------------------------------------------------------------------------
// A. Trust Decay
// -----------------------------------------------------------------------------

/// Constants governing trust decay dynamics.
pub mod trust_decay {
    /// Fraction of trust retained per idle day (5% daily decay).
    pub const DAILY_DECAY_FACTOR: f64 = 0.95;
    /// Additional multiplier applied on each DENY decision.
    pub const DENIAL_PENALTY_FACTOR: f64 = 0.80;
    /// Floor below which trust is clamped (never fully zero).
    pub const TRUST_FLOOR: f64 = 5.0;
    /// Baseline trust for a brand-new agent lineage.
    pub const INITIAL_TRUST: f64 = 75.0;
    /// Seconds per day.
    pub const SECS_PER_DAY: f64 = 86_400.0;
}

/// Compute the decayed trust score for an agent lineage.
///
/// `base_trust`        — stored trust score at `last_seen_unix_secs`
/// `last_seen_secs`    — Unix timestamp of the last observed decision
/// `now_secs`          — current Unix timestamp
/// `denial_count`      — number of DENY decisions since last_seen_secs
///
/// Returns the new trust score (clamped to `[TRUST_FLOOR, 100.0]`).
pub fn apply_trust_decay(
    base_trust: f64,
    last_seen_secs: u64,
    now_secs: u64,
    denial_count: u32,
) -> f64 {
    use trust_decay::*;
    let elapsed_days = if now_secs > last_seen_secs {
        (now_secs - last_seen_secs) as f64 / SECS_PER_DAY
    } else {
        0.0
    };
    // Exponential idle decay: trust *= 0.95^days
    let after_idle = base_trust * DAILY_DECAY_FACTOR.powf(elapsed_days);
    // Multiplicative denial penalty per denial event
    let after_denial = after_idle * DENIAL_PENALTY_FACTOR.powi(denial_count as i32);
    after_denial.clamp(TRUST_FLOOR, 100.0)
}

/// Enrich an `AgentLineage`'s trust score in-place using decay dynamics.
///
/// Call this **before** running governance on each new proposal so that
/// the Z3 totality audit sees the decayed value.
pub fn refresh_lineage_trust(lineage: &mut AgentLineage, now_secs: u64, was_denied: bool) {
    // Derive a trust score from lineage history if not already tracked.
    // We store it in `max_assessed_risk` as a proxy until the lineage struct
    // gains a dedicated field — the relationship is: higher risk → lower trust.
    let stored_trust = (100.0 - lineage.max_assessed_risk).clamp(0.0, 100.0);
    let denials = if was_denied { 1 } else { 0 };
    let new_trust = apply_trust_decay(stored_trust, lineage.last_seen_unix_secs, now_secs, denials);
    // Write back via the inverse relationship.
    lineage.max_assessed_risk = (100.0 - new_trust).clamp(0.0, 100.0);
}

// -----------------------------------------------------------------------------
// B. Delegation Chains
// -----------------------------------------------------------------------------

/// Behavioral history snapshot embedded in a DelegationToken so that receiving
/// machines can seed their local LineageRegistry without prior contact.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LineageSummary {
    /// Total governance decisions seen for this agent lifetime.
    pub decisions_seen: u32,
    /// Highest fused risk score ever assessed for this agent.
    pub max_assessed_risk: f64,
    /// Total number of DENY decisions issued against this agent.
    pub deny_count: u32,
    /// Unix timestamp of first_seen for this agent.
    pub first_seen_unix: u64,
    /// Machine hostname or ID that originally observed this agent.
    pub issuing_machine_id: String,
}

impl LineageSummary {
    /// Merge another summary into this one: max() for risk fields, sum() for counters.
    pub fn merge(&mut self, other: &LineageSummary) {
        self.decisions_seen += other.decisions_seen;
        self.deny_count += other.deny_count;
        self.max_assessed_risk = f64::max(self.max_assessed_risk, other.max_assessed_risk);
        if other.first_seen_unix > 0
            && (self.first_seen_unix == 0 || other.first_seen_unix < self.first_seen_unix)
        {
            self.first_seen_unix = other.first_seen_unix;
        }
    }
}

/// A signed capability delegation token.
///
/// Agent `delegator_id` grants `delegatee_id` the ability to act with the
/// listed `granted_intents` up to `max_risk_ceiling`, until `expiry_unix_secs`.
///
/// The token is HMAC-SHA256 signed over the canonical fields so it cannot be
/// forged or reused after the shared secret rotates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationToken {
    /// Issuing agent's registered id.
    pub delegator_id: String,
    /// Recipient agent's registered id.
    pub delegatee_id: String,
    /// Subset of the delegator's allowed_intents granted to the delegatee.
    pub granted_intents: Vec<String>,
    /// Maximum risk ceiling the delegatee may operate under (must be ≤ delegator's ceiling).
    pub max_risk_ceiling: f64,
    /// Unix timestamp after which this token is invalid.
    pub expiry_unix_secs: u64,
    /// Delegation chain depth at issuance (0 = issued by a root agent).
    pub chain_depth: u32,
    /// HMAC-SHA256 over the canonical fields, hex-encoded.
    pub signature: String,
    /// Optional behavioral history carried from the issuing machine.
    /// Advisory only — NOT included in canonical_bytes (not security-critical).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lineage_summary: Option<LineageSummary>,
}

/// Hard limit on delegation chain depth to prevent infinite re-delegation.
pub const MAX_DELEGATION_DEPTH: u32 = 3;

impl DelegationToken {
    /// Produce the canonical byte string that is signed/verified.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        format!(
            "delegator={}&delegatee={}&intents={}&ceiling={:.4}&expiry={}&depth={}",
            self.delegator_id,
            self.delegatee_id,
            self.granted_intents.join(","),
            self.max_risk_ceiling,
            self.expiry_unix_secs,
            self.chain_depth,
        )
        .into_bytes()
    }

    /// Verify the token's HMAC signature against `secret`.
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

    /// Sign this token with `secret` and store the result in `self.signature`.
    pub fn sign(&mut self, secret: &[u8]) {
        use hmac::{Hmac, KeyInit, Mac};
        use sha2::Sha256;
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(secret).expect("valid key");
        mac.update(&self.canonical_bytes());
        self.signature = hex::encode(mac.finalize().into_bytes());
    }
}

/// Error variants for delegation chain verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DelegationError {
    InvalidSignature,
    TokenExpired,
    ChainDepthExceeded,
    IntentNotGranted(String),
    RiskCeilingExceeded,
    DelegateeIdMismatch,
}

impl std::fmt::Display for DelegationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSignature => write!(f, "DELEGATION_INVALID_SIGNATURE"),
            Self::TokenExpired => write!(f, "DELEGATION_TOKEN_EXPIRED"),
            Self::ChainDepthExceeded => write!(f, "DELEGATION_CHAIN_DEPTH_EXCEEDED"),
            Self::IntentNotGranted(i) => write!(f, "DELEGATION_INTENT_NOT_GRANTED:{i}"),
            Self::RiskCeilingExceeded => write!(f, "DELEGATION_RISK_CEILING_EXCEEDED"),
            Self::DelegateeIdMismatch => write!(f, "DELEGATION_DELEGATEE_ID_MISMATCH"),
        }
    }
}

/// Verify an entire delegation chain and return the effective permission set.
///
/// # Arguments
/// * `tokens`         — ordered chain: `tokens[0]` is root delegation, `tokens[N]` is leaf
/// * `acting_agent_id` — the agent presenting the chain (must match leaf `delegatee_id`)
/// * `requested_intent` — the intent the acting agent wants to perform
/// * `requested_risk`   — the fused risk score of the current proposal
/// * `now_unix_secs`    — current time for expiry checks
/// * `secret`           — HMAC secret for signature verification
///
/// Returns `Ok(effective_ceiling)` — the minimum risk ceiling across the chain —
/// or `Err(DelegationError)` if any check fails.
pub fn verify_delegation_chain(
    tokens: &[DelegationToken],
    acting_agent_id: &str,
    requested_intent: &str,
    requested_risk: f64,
    now_unix_secs: u64,
    secret: &[u8],
) -> Result<f64, DelegationError> {
    if tokens.is_empty() {
        // No delegation chain — caller acts under their own registered permissions.
        return Ok(100.0);
    }

    // Verify the leaf token matches the acting agent.
    let leaf = tokens.last().unwrap();
    if leaf.delegatee_id != acting_agent_id {
        return Err(DelegationError::DelegateeIdMismatch);
    }

    let mut effective_ceiling = 100.0_f64;

    for (i, token) in tokens.iter().enumerate() {
        // Signature check.
        if !token.verify(secret) {
            return Err(DelegationError::InvalidSignature);
        }
        // Expiry check.
        if now_unix_secs > token.expiry_unix_secs {
            return Err(DelegationError::TokenExpired);
        }
        // Depth check.
        if token.chain_depth > MAX_DELEGATION_DEPTH {
            return Err(DelegationError::ChainDepthExceeded);
        }
        // Chain linkage: token[i].delegatee == token[i+1].delegator
        if i + 1 < tokens.len() && token.delegatee_id != tokens[i + 1].delegator_id {
            return Err(DelegationError::DelegateeIdMismatch);
        }
        // Intent intersection: requested intent must be in every token's granted_intents.
        if !token
            .granted_intents
            .iter()
            .any(|gi| gi == requested_intent)
        {
            return Err(DelegationError::IntentNotGranted(
                requested_intent.to_string(),
            ));
        }
        // Track minimum ceiling across the chain.
        effective_ceiling = effective_ceiling.min(token.max_risk_ceiling);
    }

    // Requested risk must not exceed the effective ceiling.
    if requested_risk > effective_ceiling {
        return Err(DelegationError::RiskCeilingExceeded);
    }

    Ok(effective_ceiling)
}

// -----------------------------------------------------------------------------
// C. Swarm Policy — Shared Risk Budget + Active Agent Count
// -----------------------------------------------------------------------------

/// Per-swarm policy configuration loaded from `policy.yaml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwarmPolicy {
    /// Swarm identifier — must match `agent_nodes[].swarm_id` entries.
    pub swarm_id: String,
    /// Total cumulative risk budget for this swarm. Admission is denied once
    /// the sum of `fused_risk` scores for all swarm decisions exceeds this.
    pub cumulative_risk_budget: f64,
    /// Maximum number of concurrently active (connected) swarm members.
    pub max_active_agents: u32,
    /// Whether to deny new members when the budget is exhausted (true) or
    /// just log a warning (false = soft enforcement).
    pub hard_deny_on_budget_exhausted: bool,
}

/// Thread-safe runtime budget tracker for all active swarms.
///
/// Held in `main()` as `Arc<Mutex<SharedSwarmRegistry>>` and passed into
/// every `handle_client_connection` call (analogous to `TelemetryStore`).
#[derive(Debug, Default)]
pub struct SharedSwarmRegistry {
    /// swarm_id → (used_risk_budget, active_agent_count)
    budgets: HashMap<String, (f64, u32)>,
    /// Static policy config loaded from policy.yaml at startup.
    policies: HashMap<String, SwarmPolicy>,
}

impl SharedSwarmRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Load swarm policies from a slice (called at daemon startup).
    pub fn load_policies(&mut self, policies: Vec<SwarmPolicy>) {
        for policy in policies {
            let swarm_id = policy.swarm_id.clone();
            self.policies.insert(swarm_id.clone(), policy);
            self.budgets.entry(swarm_id).or_insert((0.0, 0));
        }
    }

    /// Check whether a new agent connection is admitted for `swarm_id`.
    ///
    /// Returns `Ok(())` if admitted, `Err(reason)` if denied.
    pub fn try_admit(&mut self, swarm_id: &str) -> Result<(), String> {
        let Some(policy) = self.policies.get(swarm_id) else {
            // Unknown swarm — no policy applies, admit by default.
            return Ok(());
        };
        let entry = self.budgets.entry(swarm_id.to_string()).or_insert((0.0, 0));
        if entry.1 >= policy.max_active_agents {
            let msg = format!(
                "SWARM_DENY_ACTIVE_AGENT_LIMIT:swarm={swarm_id} limit={}",
                policy.max_active_agents
            );
            if policy.hard_deny_on_budget_exhausted {
                return Err(msg);
            }
            eprintln!("[swarm] soft warning: {msg}");
        }
        if policy.hard_deny_on_budget_exhausted && entry.0 >= policy.cumulative_risk_budget {
            return Err(format!(
                "SWARM_DENY_BUDGET_EXHAUSTED:swarm={swarm_id} used={:.2} limit={:.2}",
                entry.0, policy.cumulative_risk_budget
            ));
        }
        entry.1 += 1;
        Ok(())
    }

    /// Deduct `risk_delta` from the swarm's risk budget after a decision.
    pub fn record_decision(&mut self, swarm_id: &str, risk_delta: f64) {
        if let Some(entry) = self.budgets.get_mut(swarm_id) {
            entry.0 = (entry.0 + risk_delta).max(0.0);
        }
    }

    /// Decrement the active agent count when a connection closes.
    pub fn release_agent(&mut self, swarm_id: &str) {
        if let Some(entry) = self.budgets.get_mut(swarm_id) {
            entry.1 = entry.1.saturating_sub(1);
        }
    }

    /// Current state snapshot for diagnostics.
    pub fn budget_snapshot(&self) -> HashMap<String, (f64, u32)> {
        self.budgets.clone()
    }
}

#[cfg(test)]
mod delegation_tests {
    use super::*;

    const TEST_SECRET: &[u8] = b"delegation_test_secret_64bytes_padded_xxxxxxxxxxxxxxxxxxxxxxxxxxx";

    fn make_token(
        delegator: &str,
        delegatee: &str,
        intents: &[&str],
        ceiling: f64,
        depth: u32,
        expiry_offset: i64,
    ) -> DelegationToken {
        let now = now_unix_secs();
        let expiry = if expiry_offset >= 0 {
            now + expiry_offset as u64
        } else {
            now.saturating_sub((-expiry_offset) as u64)
        };
        let mut token = DelegationToken {
            delegator_id: delegator.to_string(),
            delegatee_id: delegatee.to_string(),
            granted_intents: intents.iter().map(|s| s.to_string()).collect(),
            max_risk_ceiling: ceiling,
            expiry_unix_secs: expiry,
            chain_depth: depth,
            signature: String::new(),
            lineage_summary: None,
        };
        token.sign(TEST_SECRET);
        token
    }

    #[test]
    fn test_delegation_lineage_merge() {
        // Build a token with an embedded LineageSummary from a "remote" machine.
        let mut token = make_token("root_agent", "child_agent", &["read_file"], 80.0, 0, 3600);
        token.lineage_summary = Some(LineageSummary {
            decisions_seen: 42,
            max_assessed_risk: 55.0,
            deny_count: 3,
            first_seen_unix: 1_700_000_000,
            issuing_machine_id: "machine-alpha".to_string(),
        });

        // Simulate a local summary that has some prior history.
        let mut local = LineageSummary {
            decisions_seen: 10,
            max_assessed_risk: 30.0,
            deny_count: 1,
            first_seen_unix: 1_700_000_500, // later than remote
            issuing_machine_id: "machine-beta".to_string(),
        };

        // Merge the remote summary.
        if let Some(remote) = &token.lineage_summary {
            local.merge(remote);
        }

        // decisions_seen and deny_count should be summed.
        assert_eq!(local.decisions_seen, 52, "decisions_seen should be summed");
        assert_eq!(local.deny_count, 4, "deny_count should be summed");
        // max_assessed_risk takes the maximum.
        assert!(
            (local.max_assessed_risk - 55.0).abs() < 0.001,
            "max risk should be 55.0"
        );
        // first_seen_unix takes the earliest timestamp.
        assert_eq!(
            local.first_seen_unix, 1_700_000_000,
            "first_seen_unix should be the earliest"
        );
    }

    #[test]
    fn test_trust_decay_idle() {
        // After 10 idle days at 0 denials, trust should drop by ~40%.
        let base = 80.0;
        let now = 1_000_000u64;
        let last_seen = now - (10 * 86_400);
        let decayed = apply_trust_decay(base, last_seen, now, 0);
        let expected = base * 0.95_f64.powi(10);
        assert!(
            (decayed - expected).abs() < 0.01,
            "decayed={decayed:.4} expected={expected:.4}"
        );
    }

    #[test]
    fn test_trust_decay_with_denial() {
        let base = 80.0;
        let now = 1_000_000u64;
        let last_seen = now; // no idle time
        let decayed = apply_trust_decay(base, last_seen, now, 2);
        let expected = (base * 0.80_f64.powi(2)).clamp(trust_decay::TRUST_FLOOR, 100.0);
        assert!((decayed - expected).abs() < 0.01);
    }

    #[test]
    fn test_trust_floor_enforced() {
        // Extreme decay should not go below TRUST_FLOOR.
        let decayed = apply_trust_decay(5.0, 0, 1_000_000, 100);
        assert!(decayed >= trust_decay::TRUST_FLOOR);
    }

    #[test]
    fn test_delegation_single_token_valid() {
        let token = make_token("root_agent", "child_agent", &["read_file"], 50.0, 0, 3600);
        let result = verify_delegation_chain(
            &[token],
            "child_agent",
            "read_file",
            30.0,
            now_unix_secs(),
            TEST_SECRET,
        );
        assert!(result.is_ok(), "expected Ok, got {result:?}");
        assert_eq!(result.unwrap(), 50.0);
    }

    #[test]
    fn test_delegation_expired_token() {
        let token = make_token("root_agent", "child_agent", &["read_file"], 50.0, 0, -1);
        let result = verify_delegation_chain(
            &[token],
            "child_agent",
            "read_file",
            10.0,
            now_unix_secs(),
            TEST_SECRET,
        );
        assert_eq!(result, Err(DelegationError::TokenExpired));
    }

    #[test]
    fn test_delegation_invalid_signature() {
        let mut token = make_token("root_agent", "child_agent", &["read_file"], 50.0, 0, 3600);
        token.signature = "deadbeef".repeat(8); // corrupt signature
        let result = verify_delegation_chain(
            &[token],
            "child_agent",
            "read_file",
            10.0,
            now_unix_secs(),
            TEST_SECRET,
        );
        assert_eq!(result, Err(DelegationError::InvalidSignature));
    }

    #[test]
    fn test_delegation_intent_not_granted() {
        let token = make_token("root_agent", "child_agent", &["read_file"], 50.0, 0, 3600);
        let result = verify_delegation_chain(
            &[token],
            "child_agent",
            "execute_shell", // not in granted_intents
            10.0,
            now_unix_secs(),
            TEST_SECRET,
        );
        assert!(matches!(result, Err(DelegationError::IntentNotGranted(_))));
    }

    #[test]
    fn test_delegation_risk_ceiling_exceeded() {
        let token = make_token(
            "root_agent",
            "child_agent",
            &["model_inference"],
            40.0,
            0,
            3600,
        );
        let result = verify_delegation_chain(
            &[token],
            "child_agent",
            "model_inference",
            55.0, // exceeds ceiling of 40.0
            now_unix_secs(),
            TEST_SECRET,
        );
        assert_eq!(result, Err(DelegationError::RiskCeilingExceeded));
    }

    #[test]
    fn test_delegation_chain_two_hops() {
        let t1 = make_token(
            "root_agent",
            "mid_agent",
            &["read_file", "model_inference"],
            60.0,
            0,
            3600,
        );
        let t2 = make_token("mid_agent", "leaf_agent", &["read_file"], 40.0, 1, 3600);
        let result = verify_delegation_chain(
            &[t1, t2],
            "leaf_agent",
            "read_file",
            35.0,
            now_unix_secs(),
            TEST_SECRET,
        );
        assert!(result.is_ok());
        // Effective ceiling is min(60, 40) = 40.
        assert_eq!(result.unwrap(), 40.0);
    }

    #[test]
    fn test_swarm_budget_admit_and_exhaust() {
        let mut registry = SharedSwarmRegistry::new();
        registry.load_policies(vec![SwarmPolicy {
            swarm_id: "swarm_alpha".to_string(),
            cumulative_risk_budget: 100.0,
            max_active_agents: 2,
            hard_deny_on_budget_exhausted: true,
        }]);

        // Two agents can join.
        assert!(registry.try_admit("swarm_alpha").is_ok());
        assert!(registry.try_admit("swarm_alpha").is_ok());
        // Third is denied (active limit).
        assert!(registry.try_admit("swarm_alpha").is_err());

        // Release one and exhaust the risk budget.
        registry.release_agent("swarm_alpha");
        registry.record_decision("swarm_alpha", 101.0); // exceeds 100.0

        // New agent should be denied (budget exhausted).
        assert!(registry.try_admit("swarm_alpha").is_err());
    }
}
