//! Human-readable decision explanations for Jinn Guard enforcement verdicts.
//!
//! This module is intentionally userspace-only. It formats decisions after the
//! enforcement verdict has already been computed.

use serde::{Deserialize, Serialize};
use std::collections::{hash_map::DefaultHasher, HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use crate::ebpf_monitor::{LsmRequest, LsmRequestType, Verdict};

pub const REPUTATION_DB_PATH: &str = "/var/lib/jinnguard/reputation.json";
const MAX_INTENT_SIGNALS_PER_PID: usize = 10;
const EXEC_WRITE_EXFIL_PATTERN: &str = "EXEC_WRITE_EXFIL";
pub const ESCALATION_THRESHOLD: u32 = 3;

static PROCESS_INTENT_MAP: OnceLock<Mutex<HashMap<u32, Vec<IntentSignal>>>> = OnceLock::new();
static PROCESS_RISK_COUNT: OnceLock<Mutex<HashMap<u32, u32>>> = OnceLock::new();
static AGENT_REPUTATION: OnceLock<Mutex<HashMap<AgentIdentity, u32>>> = OnceLock::new();

#[cfg(test)]
static INTENT_TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct AgentIdentity {
    pub process_path: Option<String>,
    pub lineage_hash: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ReputationDb {
    entries: Vec<ReputationEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ReputationEntry {
    identity: AgentIdentity,
    score: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenyReason {
    ProtectedSystemPath,
    PolicyViolation,
    UnknownAgent,
    ExecNotAllowed,
    WriteNotAllowed,
    ScopeViolation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntentSignal {
    FileWrite,
    FileDelete,
    Exec,
    NetworkAccess,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntentRiskLevel {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TrustScore(pub f32);

#[derive(Debug, Clone)]
pub struct LsmPipelineObservation {
    pub intent: IntentSignal,
    pub pattern: Option<&'static str>,
    pub risk: IntentRiskLevel,
    pub identity: AgentIdentity,
    pub trust: TrustScore,
}

#[derive(Debug, Clone)]
pub struct ExplainDecision {
    pub verdict: Verdict,
    pub reason: Option<DenyReason>,
    pub intent: Option<IntentSignal>,
    pub resource: String,
    pub process_path: Option<String>,
    pub pid: u32,
}

#[derive(Debug, Clone)]
pub struct ExplanationEvent {
    pub action_type: String,
    pub resource: Option<String>,
    pub source: Option<String>,
    pub agent_id: Option<String>,
    pub intent: Option<String>,
    pub decision: String,
    pub reason: Option<String>,
    pub enforcement_layer: String,
}

#[derive(Debug, Clone)]
pub struct ExplanationPolicy {
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct ExplanationRiskEval {
    pub risk_score: f64,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionExplanation {
    pub action_type: String,
    pub resource: Option<String>,
    pub source: Option<String>,
    pub agent_id: Option<String>,
    pub intent: Option<String>,
    pub risk_score: f64,
    pub risk_band: String,
    pub policy_name: String,
    pub decision: String,
    pub enforcement_layer: String,
    pub reasons: Vec<String>,
}

pub fn explainability_enabled() -> bool {
    env_flag_value("ENABLE_EXPLAINABILITY").unwrap_or_else(local_development_logging_default)
}

pub fn explainability_demo_enabled() -> bool {
    env_flag_enabled("ENABLE_EXPLAINABILITY_DEMO")
}

pub fn emit_explanation_if_enabled<F>(build: F)
where
    F: FnOnce() -> DecisionExplanation,
{
    if !explainability_enabled() {
        return;
    }

    let explanation = build();
    println!("{}", explanation.to_console_output());
    println!("[JINN-GUARD:JSON] {}", explanation.to_structured_log());
}

pub fn explain_deny(request: &LsmRequest, reason: DenyReason) -> Verdict {
    log_denial(request, &reason);
    Verdict::Deny
}

pub fn explain_decision(request: &LsmRequest, reason: DenyReason) -> ExplainDecision {
    ExplainDecision {
        verdict: Verdict::Deny,
        reason: Some(reason),
        intent: Some(classify_intent(request)),
        resource: request.effective_path().to_string(),
        process_path: request.process_path.clone(),
        pid: request.pid,
    }
}

pub fn log_denial(request: &LsmRequest, reason: &DenyReason) {
    let intent = classify_intent(request);
    println!(
        "[JINNGUARD DENY] pid={} process={:?} resource={} reason={:?} intent={:?}",
        request.pid,
        request.process_path,
        request.effective_path(),
        reason,
        intent
    );
}

pub fn classify_intent(request: &LsmRequest) -> IntentSignal {
    match request.req_type {
        LsmRequestType::Execve => IntentSignal::Exec,
        LsmRequestType::InodeCreate => IntentSignal::FileWrite,
        LsmRequestType::InodeUnlink => IntentSignal::FileDelete,
        LsmRequestType::Connect | LsmRequestType::SendMsg => IntentSignal::NetworkAccess,
    }
}

pub fn observe_lsm_request(request: &LsmRequest, track_state: bool) -> LsmPipelineObservation {
    let intent = classify_intent(request);
    println!(
        "[JINNGUARD EVENT] pid={} type={:?} resource={} process={:?}",
        request.pid,
        request.req_type,
        request.effective_path(),
        request.process_path
    );
    println!("[JINNGUARD INTENT] pid={} signal={:?}", request.pid, intent);

    let (pattern, risk) = if track_state {
        record_intent(request, intent.clone())
    } else {
        (None, classify_intent_risk(None))
    };
    println!(
        "[JINNGUARD RISK] pid={} risk={:?} pattern={:?}",
        request.pid, risk, pattern
    );

    let identity = compute_agent_identity(request);
    let trust = get_agent_trust(&identity);

    LsmPipelineObservation {
        intent,
        pattern,
        risk,
        identity,
        trust,
    }
}

pub fn record_intent(
    request: &LsmRequest,
    signal: IntentSignal,
) -> (Option<&'static str>, IntentRiskLevel) {
    let map = PROCESS_INTENT_MAP.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = map.lock().unwrap_or_else(|err| err.into_inner());
    let signals = guard.entry(request.pid).or_default();

    signals.push(signal);
    if signals.len() > MAX_INTENT_SIGNALS_PER_PID {
        let remove_count = signals.len() - MAX_INTENT_SIGNALS_PER_PID;
        signals.drain(0..remove_count);
    }

    let pattern = if has_exec_write_exfil_pattern(signals) {
        Some(EXEC_WRITE_EXFIL_PATTERN)
    } else {
        None
    };
    let risk = classify_intent_risk(pattern);

    if risk == IntentRiskLevel::High {
        increment_high_risk_count(request.pid);
        increment_agent_reputation(request);
        println!(
            "[JINNGUARD INTENT] pid={} pattern={}",
            request.pid, EXEC_WRITE_EXFIL_PATTERN
        );
    }

    (pattern, risk)
}

pub fn classify_intent_risk(pattern: Option<&str>) -> IntentRiskLevel {
    match pattern {
        Some(EXEC_WRITE_EXFIL_PATTERN) => IntentRiskLevel::High,
        _ => IntentRiskLevel::Low,
    }
}

fn has_exec_write_exfil_pattern(signals: &[IntentSignal]) -> bool {
    matches!(
        signals.windows(3).last(),
        Some([
            IntentSignal::Exec,
            IntentSignal::FileWrite,
            IntentSignal::NetworkAccess
        ])
    )
}

fn increment_high_risk_count(pid: u32) -> u32 {
    let map = PROCESS_RISK_COUNT.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = map.lock().unwrap_or_else(|err| err.into_inner());
    let count = guard.entry(pid).or_insert(0);
    *count = count.saturating_add(1);

    if *count == ESCALATION_THRESHOLD {
        println!(
            "[JINNGUARD ESCALATION]\npid={}\nlevel=REPEATED_HIGH_RISK",
            pid
        );
    }

    *count
}

pub fn is_escalated(pid: u32) -> bool {
    let map = PROCESS_RISK_COUNT.get_or_init(|| Mutex::new(HashMap::new()));
    let guard = map.lock().unwrap_or_else(|err| err.into_inner());
    guard
        .get(&pid)
        .is_some_and(|count| *count >= ESCALATION_THRESHOLD)
}

pub fn compute_agent_identity(request: &LsmRequest) -> AgentIdentity {
    let process_path = request.process_path.clone();
    let parent_pid = process_parent_pid(request.pid).unwrap_or(0);
    let mut hasher = DefaultHasher::new();
    process_path.hash(&mut hasher);
    parent_pid.hash(&mut hasher);

    AgentIdentity {
        process_path,
        lineage_hash: hasher.finish(),
    }
}

fn process_parent_pid(pid: u32) -> Option<u32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let (_comm, fields) = stat.rsplit_once(") ")?;
    let mut fields = fields.split_whitespace();

    // Fields after comm: state, ppid, pgrp, session, tty_nr, ...
    let _state = fields.next()?;
    fields.next()?.parse::<u32>().ok()
}

fn increment_agent_reputation(request: &LsmRequest) -> u32 {
    let identity = compute_agent_identity(request);
    let map = AGENT_REPUTATION.get_or_init(|| Mutex::new(load_reputation()));
    let (score, snapshot) = {
        let mut guard = map.lock().unwrap_or_else(|err| err.into_inner());
        let score = guard.entry(identity.clone()).or_insert(0);
        *score = score.saturating_add(1);
        (*score, guard.clone())
    };

    let status = if score >= ESCALATION_THRESHOLD {
        "ESCALATED"
    } else {
        "TRACKING"
    };
    println!(
        "[JINNGUARD REPUTATION]\nidentity={:?}\nscore={}\nstatus={}",
        identity, score, status
    );

    if let Err(err) = save_reputation(&snapshot) {
        eprintln!(
            "[JINNGUARD PERSIST] warning: failed to save reputation DB: {}",
            err
        );
    }

    score
}

pub fn is_agent_escalated(identity: &AgentIdentity) -> bool {
    let map = AGENT_REPUTATION.get_or_init(|| Mutex::new(load_reputation()));
    let guard = map.lock().unwrap_or_else(|err| err.into_inner());
    guard
        .get(identity)
        .is_some_and(|score| *score >= ESCALATION_THRESHOLD)
}

pub fn compute_trust(score: u32) -> TrustScore {
    let value = 1.0 - (score as f32 / 10.0);
    TrustScore(value.max(0.0))
}

pub fn get_agent_trust(identity: &AgentIdentity) -> TrustScore {
    let map = AGENT_REPUTATION.get_or_init(|| Mutex::new(load_reputation()));
    let guard = map.lock().unwrap_or_else(|err| err.into_inner());
    let score = guard.get(identity).copied().unwrap_or(0);
    let trust = compute_trust(score);
    println!(
        "[JINNGUARD TRUST]\nidentity={:?}\ntrust_score={}",
        identity, trust.0
    );
    trust
}

pub fn load_reputation() -> HashMap<AgentIdentity, u32> {
    load_reputation_from_path(&reputation_db_path())
}

fn save_reputation(map: &HashMap<AgentIdentity, u32>) -> std::io::Result<()> {
    save_reputation_to_path(&reputation_db_path(), map)
}

fn reputation_db_path() -> PathBuf {
    if let Ok(path) = std::env::var("JINNGUARD_REPUTATION_DB_PATH") {
        if !path.trim().is_empty() {
            return PathBuf::from(path);
        }
    }

    #[cfg(test)]
    {
        return std::env::temp_dir().join("jinnguard-reputation-test.json");
    }

    #[cfg(not(test))]
    {
        PathBuf::from(REPUTATION_DB_PATH)
    }
}

fn load_reputation_from_path(path: &Path) -> HashMap<AgentIdentity, u32> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return HashMap::new(),
        Err(err) => {
            eprintln!(
                "[JINNGUARD PERSIST] warning: failed to read reputation DB {}: {}; resetting",
                path.display(),
                err
            );
            return HashMap::new();
        }
    };

    match serde_json::from_slice::<ReputationDb>(&bytes) {
        Ok(db) => db
            .entries
            .into_iter()
            .map(|entry| (entry.identity, entry.score))
            .collect(),
        Err(err) => {
            eprintln!(
                "[JINNGUARD PERSIST] warning: failed to parse reputation DB {}: {}; resetting",
                path.display(),
                err
            );
            HashMap::new()
        }
    }
}

fn save_reputation_to_path(path: &Path, map: &HashMap<AgentIdentity, u32>) -> std::io::Result<()> {
    let db = ReputationDb {
        entries: map
            .iter()
            .map(|(identity, score)| ReputationEntry {
                identity: identity.clone(),
                score: *score,
            })
            .collect(),
    };
    let bytes = serde_json::to_vec_pretty(&db)?;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("reputation.json");
    let tmp_path = path.with_file_name(format!("{}.{}.tmp", file_name, std::process::id()));

    std::fs::write(&tmp_path, bytes)?;
    std::fs::rename(&tmp_path, path)?;
    println!("[JINNGUARD PERSIST] saved reputation entries={}", map.len());
    Ok(())
}

#[cfg(test)]
pub fn clear_intent_tracking_for_test() {
    let map = PROCESS_INTENT_MAP.get_or_init(|| Mutex::new(HashMap::new()));
    map.lock().unwrap_or_else(|err| err.into_inner()).clear();

    let risk_map = PROCESS_RISK_COUNT.get_or_init(|| Mutex::new(HashMap::new()));
    risk_map
        .lock()
        .unwrap_or_else(|err| err.into_inner())
        .clear();

    let reputation = AGENT_REPUTATION.get_or_init(|| Mutex::new(load_reputation()));
    reputation
        .lock()
        .unwrap_or_else(|err| err.into_inner())
        .clear();

    let _ = std::fs::remove_file(reputation_db_path());
}

#[cfg(test)]
fn replace_reputation_for_test(map: HashMap<AgentIdentity, u32>) {
    let reputation = AGENT_REPUTATION.get_or_init(|| Mutex::new(load_reputation()));
    *reputation.lock().unwrap_or_else(|err| err.into_inner()) = map;
}

#[cfg(test)]
pub fn intent_tracking_test_guard() -> std::sync::MutexGuard<'static, ()> {
    INTENT_TEST_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|err| err.into_inner())
}

pub fn build_explanation(
    event: ExplanationEvent,
    policy: ExplanationPolicy,
    risk_eval: ExplanationRiskEval,
) -> DecisionExplanation {
    let risk_score = risk_eval.risk_score.clamp(0.0, 100.0);
    let risk_band = risk_band_for_score(risk_score).to_string();
    let decision = event.decision.trim().to_ascii_uppercase();

    let mut reasons = Vec::new();
    let mut seen = HashSet::new();

    if let Some(reason) = event.reason.as_deref() {
        push_reason(&mut reasons, &mut seen, humanize_reason(reason));
    }

    for reason in risk_eval.reasons {
        push_reason(&mut reasons, &mut seen, humanize_reason(&reason));
    }

    append_decision_context(
        &mut reasons,
        &mut seen,
        &decision,
        &risk_band,
        &event.intent,
        risk_score,
    );

    DecisionExplanation {
        action_type: event.action_type,
        resource: event.resource,
        source: event.source,
        agent_id: event.agent_id,
        intent: event.intent,
        risk_score,
        risk_band,
        policy_name: policy.name,
        decision,
        enforcement_layer: event.enforcement_layer,
        reasons,
    }
}

/// Neutralise control characters (newline/CR/tab/etc.) in a field before it is
/// written to the **human** console explanation (JG-RT-005). The attacker controls
/// `agent_id`, the resource path and the action name; without this, an embedded
/// `\n[JINN-GUARD] ALLOW …` could forge a fake decision line in the console log.
/// The structured `to_structured_log` channel is already injection-safe (serde).
fn sanitize_log_field(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { '\u{FFFD}' } else { c })
        .collect()
}

impl DecisionExplanation {
    pub fn to_console_output(&self) -> String {
        let action = sanitize_log_field(&self.action_type.replace('_', " ").to_ascii_uppercase());
        let target = sanitize_log_field(
            self.resource
                .as_deref()
                .or(self.intent.as_deref())
                .unwrap_or(&self.action_type),
        );
        let source = self.source.as_deref().unwrap_or("unknown");
        let agent = sanitize_log_field(self.agent_id.as_deref().unwrap_or("anonymous/unknown"));
        let decision_summary = match self.decision.as_str() {
            "ALLOW" => "ALLOWED",
            "CONSTRAIN" => "CONSTRAINED",
            _ => "DENIED",
        };
        let risk_context = risk_context_label(&self.risk_band, &self.decision);
        let enforcement_lines = match self.decision.as_str() {
            "ALLOW" => vec![
                "- Action permitted by current policy".to_string(),
                "- Execution may proceed through the selected enforcement layer".to_string(),
            ],
            "CONSTRAIN" => vec![
                "- Action permitted only with constraints".to_string(),
                "- Guardrails remain active during execution".to_string(),
            ],
            _ => vec![
                "- Action blocked before execution".to_string(),
                "- No side effects permitted".to_string(),
            ],
        };

        let reason_lines = self
            .reasons
            .iter()
            .map(|reason| format!("- {}", sanitize_log_field(reason)))
            .collect::<Vec<_>>()
            .join("\n");

        format!(
            "[JINN-GUARD] {} {}\n\n\
             Target: {}\n\
             Source: {}\n\
             Agent: {}\n\n\
             Decision Summary:\n\
             - Action: {}\n\
             - Policy: {}\n\
             - Risk Score: {:.2} ({})\n\
             - Enforcement Layer: {}\n\n\
             Reason Chain:\n{}\n\n\
             Enforcement:\n{}",
            self.decision,
            action,
            target,
            source,
            agent,
            decision_summary,
            self.policy_name,
            self.risk_score,
            risk_context,
            self.enforcement_layer,
            reason_lines,
            enforcement_lines.join("\n")
        )
    }

    pub fn to_structured_log(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string())
    }
}

pub fn print_demo_decision(action: &str, allow_or_deny: &str) {
    let decision = if allow_or_deny.eq_ignore_ascii_case("allow") {
        "ALLOW"
    } else {
        "DENY"
    };
    let risk_score = if decision == "ALLOW" { 12.0 } else { 55.0 };
    let reason = if decision == "ALLOW" {
        "policy_allow"
    } else {
        "mid_band_risk_constrained"
    };

    let explanation = build_explanation(
        ExplanationEvent {
            action_type: action.to_string(),
            resource: Some(action.to_string()),
            source: Some("demo_terminal".to_string()),
            agent_id: Some("demo_agent".to_string()),
            intent: Some(action.to_string()),
            decision: decision.to_string(),
            reason: Some(reason.to_string()),
            enforcement_layer: "gateway".to_string(),
        },
        ExplanationPolicy {
            name: "runtime_governance".to_string(),
        },
        ExplanationRiskEval {
            risk_score,
            reasons: vec![reason.to_string()],
        },
    );

    println!("{}", explanation.to_console_output());
    println!("[JINN-GUARD:JSON] {}", explanation.to_structured_log());
}

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

fn local_development_logging_default() -> bool {
    !env_flag_enabled("JINNGUARD_ENTERPRISE") && std::io::stdout().is_terminal()
}

fn risk_band_for_score(score: f64) -> &'static str {
    if score >= 75.0 {
        "high"
    } else if score >= 40.0 {
        "mid"
    } else {
        "low"
    }
}

fn risk_context_label(risk_band: &str, decision: &str) -> &'static str {
    match (risk_band, decision) {
        ("low", "ALLOW") => "low-band allowed",
        ("mid", "CONSTRAIN") => "mid-band constrained",
        ("mid", "DENY") => "mid-band denied",
        ("high", "DENY") => "high-band denied",
        ("high", _) => "high-band elevated",
        ("mid", _) => "mid-band elevated",
        _ => "low-band risk",
    }
}

fn append_decision_context(
    reasons: &mut Vec<String>,
    seen: &mut HashSet<String>,
    decision: &str,
    risk_band: &str,
    intent: &Option<String>,
    risk_score: f64,
) {
    match risk_band {
        "high" => push_reason(
            reasons,
            seen,
            "Risk score is in the high-risk range for this policy".to_string(),
        ),
        "mid" => push_reason(
            reasons,
            seen,
            "Risk score falls within the constrained range".to_string(),
        ),
        _ => push_reason(
            reasons,
            seen,
            "Risk score is below the elevated-risk threshold".to_string(),
        ),
    }

    if intent.is_none() && decision != "ALLOW" {
        push_reason(
            reasons,
            seen,
            "Intent was not declared, so policy could not authorize it explicitly".to_string(),
        );
    }

    match decision {
        "ALLOW" => push_reason(
            reasons,
            seen,
            "Policy permits the declared action at the assessed risk level".to_string(),
        ),
        "CONSTRAIN" => push_reason(
            reasons,
            seen,
            "Policy permits the action only with additional constraints".to_string(),
        ),
        _ => {
            push_reason(
                reasons,
                seen,
                "Policy does not permit this action under current governance rules".to_string(),
            );
            if risk_score >= 40.0 {
                push_reason(
                    reasons,
                    seen,
                    "Identity or token checks may be valid but are insufficient for this action"
                        .to_string(),
                );
            }
        }
    }
}

fn push_reason(reasons: &mut Vec<String>, seen: &mut HashSet<String>, reason: String) {
    let trimmed = reason.trim();
    if trimmed.is_empty() {
        return;
    }
    let key = trimmed.to_ascii_lowercase();
    if seen.insert(key) {
        reasons.push(trimmed.to_string());
    }
}

fn humanize_reason(reason: &str) -> String {
    match reason {
        "policy_allow" => "Policy allowlist and risk checks passed".to_string(),
        "mid_band_risk_constrained" => "Risk score falls within constrained range".to_string(),
        "risk_ceiling_exceeded" => "Risk score exceeds the configured safety ceiling".to_string(),
        "trust_floor_breached" => "Trust score is below the configured minimum".to_string(),
        "intent_not_allowed" | "DENY_INTENT_NOT_ALLOWED" => {
            "Intent not declared or not allowed".to_string()
        }
        "anonymous_agent_not_permitted" | "DENY_ANONYMOUS_AGENT_NOT_PERMITTED" => {
            "Anonymous agents are not permitted by policy".to_string()
        }
        "unknown_agent_id" | "DENY_UNKNOWN_AGENT_ID" => {
            "Agent identity is not registered in policy".to_string()
        }
        "replay_attack" | "DENY_REPLAY_ATTACK" => {
            "Sequence counter was already seen for this agent".to_string()
        }
        "tampered_token" | "DENY_TAMPERED_TOKEN" => {
            "HMAC verification failed; payload may have been tampered with".to_string()
        }
        "malformed_payload" | "DENY_MALFORMED_PAYLOAD" => {
            "Request payload could not be parsed safely".to_string()
        }
        "DENY_PAYLOAD_TOO_LARGE" => {
            "Request payload exceeds the maximum permitted size".to_string()
        }
        "DENY_ENCODING_ERROR" => "Request payload is not valid UTF-8".to_string(),
        "DENY_DELEGATION_INVALID" => "Delegation token failed validity checks".to_string(),
        "DENY_DELEGATION_UNSUPPORTED" => {
            "Delegation token format is not supported by this policy".to_string()
        }
        "bad_version" | "DENY_BAD_VERSION" => "Protocol version is unsupported".to_string(),
        "runtime_policy" | "DENY_RUNTIME_POLICY" => {
            "Runtime sandbox policy rejected the proposed action".to_string()
        }
        "quota_exhausted" | "DENY_QUOTA_EXHAUSTED" => {
            "Agent sequence quota has been exhausted".to_string()
        }
        "policy_invariant_violated" => {
            "Formal policy invariant verification rejected the proposal".to_string()
        }
        "risk_within_policy" => "Risk and trust scores are within policy limits".to_string(),
        "kernel_policy_map_allow" => "Kernel policy map permitted this operation".to_string(),
        "kernel_policy_map_deny" => "Kernel policy map denied this operation".to_string(),
        "system_process_immunity" => "Base system process matched the immunity matrix".to_string(),
        "system_command_immunity" => "Base system command matched the immunity matrix".to_string(),
        "outside_enforcement_scope" => {
            "Resource is outside the active enforcement scope".to_string()
        }
        "protected_resource_proposed_action" => {
            "Explicit proposed action targets a protected system resource".to_string()
        }
        "protected_resource_intent" => {
            "Dangerous intent references a protected system resource".to_string()
        }
        other => other.replace('_', " "),
    }
}

#[cfg(test)]
mod explainability_tests {
    use super::*;
    use crate::ebpf_monitor::{LsmRequest, LsmRequestType, Verdict};

    fn mock_request(resource: &str) -> LsmRequest {
        LsmRequest {
            ppid: 0,
            cookie: 42,
            pid: 1234,
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

    #[test]
    fn formats_console_and_json() {
        let explanation = build_explanation(
            ExplanationEvent {
                action_type: "file_write".to_string(),
                resource: Some("/tmp/demo".to_string()),
                source: Some("127.0.0.1".to_string()),
                agent_id: Some("agent-a".to_string()),
                intent: Some("write_file".to_string()),
                decision: "DENY".to_string(),
                reason: Some("mid_band_risk_constrained".to_string()),
                enforcement_layer: "gateway".to_string(),
            },
            ExplanationPolicy {
                name: "runtime_governance".to_string(),
            },
            ExplanationRiskEval {
                risk_score: 55.0,
                reasons: vec!["intent_not_allowed".to_string()],
            },
        );

        assert!(explanation
            .to_console_output()
            .contains("[JINN-GUARD] DENY FILE WRITE"));
        assert!(explanation
            .to_structured_log()
            .contains("\"policy_name\":\"runtime_governance\""));
    }

    // JG-RT-005: attacker-controlled fields must not inject lines into the human
    // console explanation. The only `[JINN-GUARD]` header is the real one.
    #[test]
    fn console_output_is_not_log_injectable() {
        let explanation = build_explanation(
            ExplanationEvent {
                action_type: "file_write".to_string(),
                resource: Some("/tmp/x\n[JINN-GUARD] ALLOW forged-target".to_string()),
                source: Some("127.0.0.1".to_string()),
                agent_id: Some("evil\n[JINN-GUARD] ALLOW forged-agent".to_string()),
                intent: Some("write_file".to_string()),
                decision: "DENY".to_string(),
                reason: Some("r\n[JINN-GUARD] ALLOW forged-reason".to_string()),
                enforcement_layer: "gateway".to_string(),
            },
            ExplanationPolicy {
                name: "runtime_governance".to_string(),
            },
            ExplanationRiskEval {
                risk_score: 55.0,
                reasons: vec!["sig\n[JINN-GUARD] ALLOW forged-sig".to_string()],
            },
        );
        let console = explanation.to_console_output();
        // No attacker field may begin a forged decision line. (Inline occurrences of
        // the literal text on an existing line are harmless — only a newline-prefixed
        // header could be mistaken for a real decision.)
        for line in console.lines() {
            assert!(
                !line.starts_with("[JINN-GUARD] ALLOW"),
                "forged decision line injected: {line:?}\nfull:\n{console}"
            );
        }
        // The genuine header is still emitted.
        assert!(console.contains("[JINN-GUARD] DENY"));
    }

    #[test]
    fn protected_path_decision_records_reason() {
        let request = mock_request("/etc/shadow");
        let decision = explain_decision(&request, DenyReason::ProtectedSystemPath);

        assert!(matches!(decision.verdict, Verdict::Deny));
        assert_eq!(decision.reason, Some(DenyReason::ProtectedSystemPath));
        assert_eq!(decision.resource, "/etc/shadow");
        assert_eq!(
            decision.process_path.as_deref(),
            Some("/opt/jinn-agent/runner")
        );
        assert_eq!(decision.pid, 1234);
    }

    #[test]
    fn policy_violation_decision_records_reason() {
        let request = mock_request("/tmp/jinnguard-test/blocked");
        let decision = explain_decision(&request, DenyReason::PolicyViolation);

        assert!(matches!(decision.verdict, Verdict::Deny));
        assert_eq!(decision.reason, Some(DenyReason::PolicyViolation));
        assert_eq!(decision.resource, "/tmp/jinnguard-test/blocked");
    }

    #[test]
    fn explain_deny_logs_without_panicking() {
        let request = mock_request("/tmp/jinnguard-test/logged");
        let verdict = explain_deny(&request, DenyReason::PolicyViolation);

        assert!(matches!(verdict, Verdict::Deny));
    }
}

#[cfg(test)]
mod persistence_tests {
    use super::{
        classify_intent, clear_intent_tracking_for_test, compute_agent_identity, compute_trust,
        get_agent_trust, intent_tracking_test_guard, is_agent_escalated, load_reputation_from_path,
        record_intent, replace_reputation_for_test, save_reputation_to_path, AgentIdentity,
        ESCALATION_THRESHOLD,
    };
    use crate::ebpf_monitor::{LsmRequest, LsmRequestType};
    use std::collections::HashMap;
    use std::path::PathBuf;

    fn test_db_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "jinnguard-reputation-{}-{}.json",
            name,
            std::process::id()
        ))
    }

    fn mock_request(pid: u32, req_type: LsmRequestType, process_path: &str) -> LsmRequest {
        LsmRequest {
            ppid: 0,
            cookie: 42,
            pid,
            req_type,
            source_program: 0,
            family: 0,
            tty: None,
            is_interactive: false,
            process_path: Some(process_path.to_string()),
            resource: "/tmp/jinnguard-test/reputation".to_string(),
            resolved_path: None,
            payload_preview: vec![],
        }
    }

    fn drive_high_risk_sequence(pid: u32, process_path: &str) {
        let exec = mock_request(pid, LsmRequestType::Execve, process_path);
        let write = mock_request(pid, LsmRequestType::InodeCreate, process_path);
        let network = mock_request(pid, LsmRequestType::Connect, process_path);

        let _ = record_intent(&exec, classify_intent(&exec));
        let _ = record_intent(&write, classify_intent(&write));
        let _ = record_intent(&network, classify_intent(&network));
    }

    #[test]
    fn save_and_reload_reputation_values() {
        let _guard = intent_tracking_test_guard();
        let path = test_db_path("save-reload");
        let _ = std::fs::remove_file(&path);
        let identity = AgentIdentity {
            process_path: Some("/opt/jinn-agent/persist".to_string()),
            lineage_hash: 42,
        };
        let mut map = HashMap::new();
        map.insert(identity.clone(), 2);

        save_reputation_to_path(&path, &map).expect("save reputation DB");
        let loaded = load_reputation_from_path(&path);

        assert_eq!(loaded.get(&identity), Some(&2));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn restart_simulation_continues_escalation_from_reloaded_state() {
        let _guard = intent_tracking_test_guard();
        clear_intent_tracking_for_test();
        let path = test_db_path("restart");
        let _ = std::fs::remove_file(&path);
        let request = mock_request(830_001, LsmRequestType::Connect, "/opt/jinn-agent/persist");
        let identity = compute_agent_identity(&request);
        let mut prior = HashMap::new();
        prior.insert(identity.clone(), ESCALATION_THRESHOLD - 1);

        save_reputation_to_path(&path, &prior).expect("save prior reputation");
        replace_reputation_for_test(load_reputation_from_path(&path));
        drive_high_risk_sequence(830_001, "/opt/jinn-agent/persist");

        assert!(is_agent_escalated(&identity));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn corrupt_reputation_file_recovers_safely() {
        let _guard = intent_tracking_test_guard();
        let path = test_db_path("corrupt");
        std::fs::write(&path, b"{ not valid json").expect("write corrupt reputation DB");

        let loaded = load_reputation_from_path(&path);

        assert!(loaded.is_empty());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn high_reputation_produces_low_trust() {
        let _guard = intent_tracking_test_guard();
        clear_intent_tracking_for_test();

        assert!(compute_trust(8).0 < 0.5);
        assert_eq!(compute_trust(20).0, 0.0);
    }

    #[test]
    fn low_or_missing_reputation_produces_high_trust() {
        let _guard = intent_tracking_test_guard();
        clear_intent_tracking_for_test();
        let identity = AgentIdentity {
            process_path: Some("/opt/jinn-agent/new".to_string()),
            lineage_hash: 7,
        };

        assert_eq!(compute_trust(0).0, 1.0);
        assert!(get_agent_trust(&identity).0 >= 0.9);
    }
}

#[cfg(test)]
mod intent_tracking_tests {
    use super::{
        classify_intent, clear_intent_tracking_for_test, intent_tracking_test_guard,
        observe_lsm_request, record_intent, IntentSignal, EXEC_WRITE_EXFIL_PATTERN,
    };
    use crate::ebpf_monitor::{LsmRequest, LsmRequestType};

    fn mock_request(pid: u32, req_type: LsmRequestType, resource: &str) -> LsmRequest {
        LsmRequest {
            ppid: 0,
            cookie: 42,
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

    #[test]
    fn classifies_exec_request_intent() {
        let request = mock_request(700_001, LsmRequestType::Execve, "/tmp/jinnguard-test/tool");

        assert_eq!(classify_intent(&request), IntentSignal::Exec);
    }

    #[test]
    fn observes_lsm_request_pipeline_fields() {
        let _guard = intent_tracking_test_guard();
        clear_intent_tracking_for_test();
        let request = mock_request(700_004, LsmRequestType::Execve, "/tmp/jinnguard-test/tool");

        let observation = observe_lsm_request(&request, true);

        assert_eq!(observation.intent, IntentSignal::Exec);
        assert_eq!(observation.pattern, None);
        assert_eq!(observation.risk, super::IntentRiskLevel::Low);
        assert_eq!(
            observation.identity.process_path.as_deref(),
            Some("/opt/jinn-agent/runner")
        );
        assert_eq!(observation.trust.0, 1.0);
    }

    #[test]
    fn records_exec_write_network_sequence_pattern() {
        let _guard = intent_tracking_test_guard();
        clear_intent_tracking_for_test();
        let pid = 700_002;
        let exec = mock_request(pid, LsmRequestType::Execve, "/tmp/jinnguard-test/tool");
        let write = mock_request(pid, LsmRequestType::InodeCreate, "/tmp/jinnguard-test/file");
        let network = mock_request(pid, LsmRequestType::Connect, "203.0.113.10:443");

        assert_eq!(
            record_intent(&exec, classify_intent(&exec)),
            (None, super::IntentRiskLevel::Low)
        );
        assert_eq!(
            record_intent(&write, classify_intent(&write)),
            (None, super::IntentRiskLevel::Low)
        );
        assert_eq!(
            record_intent(&network, classify_intent(&network)),
            (Some(EXEC_WRITE_EXFIL_PATTERN), super::IntentRiskLevel::High)
        );
    }

    #[test]
    fn repeated_signal_recording_does_not_panic() {
        let _guard = intent_tracking_test_guard();
        clear_intent_tracking_for_test();
        let request = mock_request(700_003, LsmRequestType::SendMsg, "203.0.113.10:443");

        for _ in 0..64 {
            let _ = record_intent(&request, IntentSignal::NetworkAccess);
        }
    }
}
