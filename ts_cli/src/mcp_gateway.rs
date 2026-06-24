//! MCP Gateway — HTTP/1.1 inline enforcement proxy for Model Context Protocol servers.
//!
//! # Architecture
//! 1. Bind a TCP listener on `--mcp-port` (default: 4750).
//! 2. For each connection, read a full HTTP/1.1 request (headers + body).
//! 3. Parse the JSON-RPC body: map `method` → `intent_name`, `params` → `context_vars`.
//! 4. Build a `ClientProposal` and run it through the governance enforcement pipeline.
//! 5. **ALLOW**: forward to upstream (`--mcp-upstream`) and stream the response back.
//! 6. **DENY**: return HTTP 403 with the deny signal as the JSON body.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod, SslVerifyMode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::{
    explainability::{
        build_explanation, emit_explanation_if_enabled, ExplanationEvent, ExplanationPolicy,
        ExplanationRiskEval,
    },
    explicit_protected_resource_attack,
    governance::{
        AgentLineage, AuditLogger, CapabilityProfile, ClientProposal, CombinedSemanticService,
        ExecutionBroker, ExecutionRequest, IntentClass, LineageRegistry, ObservationRecord,
        PolicyDecision, RiskAssessment, SemanticAnalysisService, SemanticIntent,
    },
    intent_is_dangerous, is_enforcement_target, observed_risk_penalty, policy_decision,
    protected_resource_reference, system_immunity, KernelTelemetryEvent, PolicyConfig,
    TelemetryStore,
};

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct JsonRpcRequest {
    #[allow(dead_code)]
    jsonrpc: Option<String>,
    method: String,
    #[serde(default)]
    params: Value,
    #[serde(default)]
    id: Value,
}

#[derive(Debug, Serialize)]
struct JsonRpcError {
    jsonrpc: &'static str,
    id: Value,
    error: JsonRpcErrorObj,
}

#[derive(Debug, Serialize)]
struct JsonRpcErrorObj {
    code: i64,
    message: String,
    data: Option<Value>,
}

// ---------------------------------------------------------------------------
// Synthetic agent_id derivation
// ---------------------------------------------------------------------------

/// Derive a deterministic synthetic agent_id from the client IP address using
/// an HMAC-SHA256 over the IP string.  This allows the governance pipeline to
/// track per-IP behavioral lineage without requiring the caller to register.
fn synthetic_agent_id(peer_ip: &str, secret: &[u8]) -> String {
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;
    type H = Hmac<Sha256>;
    let mut mac =
        H::new_from_slice(secret).unwrap_or_else(|_| H::new_from_slice(b"fallback").unwrap());
    mac.update(peer_ip.as_bytes());
    let hash = hex::encode(mac.finalize().into_bytes());
    format!("mcp_gw_{}", &hash[..16])
}

fn emit_mcp_decision_explanation(
    decision: &str,
    reason: &str,
    peer_ip: &str,
    method: &str,
    agent_id: &str,
    assessment: &RiskAssessment,
) {
    emit_explanation_if_enabled(|| {
        let mut reasons = assessment.reasons.clone();
        reasons.push(reason.to_string());

        build_explanation(
            ExplanationEvent {
                action_type: method.to_string(),
                resource: Some(method.to_string()),
                source: Some(peer_ip.to_string()),
                agent_id: Some(agent_id.to_string()),
                intent: Some(method.to_string()),
                decision: decision.to_string(),
                reason: Some(reason.to_string()),
                enforcement_layer: "gateway".to_string(),
            },
            ExplanationPolicy {
                name: "runtime_governance".to_string(),
            },
            ExplanationRiskEval {
                risk_score: assessment.fused_risk,
                reasons,
            },
        )
    });
}

fn mcp_immunity_assessment(reason: &str) -> RiskAssessment {
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

fn mcp_immunity_intent(method: &str, reason: &str) -> SemanticIntent {
    let class = if method.contains("exec") || method.contains("command") {
        IntentClass::ProcessExecution
    } else if method.contains("write") || method.contains("unlink") {
        IntentClass::FileWrite
    } else if method.contains("connect") || method.contains("network") {
        IntentClass::NetworkAccess
    } else {
        IntentClass::Unknown
    };

    SemanticIntent {
        class,
        confidence: 1.0,
        risk_score: 0.0,
        signals: vec![reason.to_string()],
    }
}

fn mcp_enforcement_path(params: &Value) -> Option<&str> {
    if let Some(obj) = params.as_object() {
        for key in ["path", "resource", "target", "file_path", "executable"] {
            if let Some(path) = obj
                .get(key)
                .and_then(|value| value.as_str())
                .filter(|value| !value.trim().is_empty())
            {
                return Some(path);
            }
        }
    }

    None
}

fn mcp_requires_intent_aware_enforcement(
    method: &str,
    params: &Value,
    resource_path: Option<&str>,
    action_risk_score: Option<f64>,
    risk_floor: f64,
) -> bool {
    intent_is_dangerous(method)
        || action_risk_score.is_some_and(|risk| risk >= risk_floor)
        || resource_path.is_some_and(protected_resource_reference)
        || params_contains_protected_resource(params)
}

fn params_contains_protected_resource(value: &Value) -> bool {
    match value {
        Value::String(s) => protected_resource_reference(s),
        Value::Array(values) => values.iter().any(params_contains_protected_resource),
        Value::Object(map) => map.values().any(params_contains_protected_resource),
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// HTTP/1.1 minimal parser
// ---------------------------------------------------------------------------

/// Upper bound on an MCP request body, in bytes. A `Content-Length` above this is
/// refused before any body buffer is allocated, so a hostile header cannot drive an
/// unbounded allocation (JG-RT-001). Matches the UDS wire protocol's 4 MiB ceiling.
const MAX_MCP_BODY_BYTES: usize = 4 * 1024 * 1024;
const MAX_MCP_UPSTREAM_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const MCP_REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(5);
const MCP_UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const MCP_UPSTREAM_RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);

struct HttpRequest {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

/// Read a minimal HTTP/1.1 request from a tokio TcpStream.
/// Supports chunked detection but does not decode chunks — the body is read
/// by Content-Length only, which is the norm for JSON-RPC clients.
async fn read_http_request<S: AsyncRead + Unpin>(stream: &mut S) -> anyhow::Result<HttpRequest> {
    let mut raw = Vec::with_capacity(4096);

    // Read until we see \r\n\r\n (end of headers).
    let header_end = loop {
        let mut byte = [0u8; 1];
        if stream.read_exact(&mut byte).await.is_err() {
            anyhow::bail!("connection closed before headers complete");
        }
        raw.push(byte[0]);
        if raw.ends_with(b"\r\n\r\n") {
            break raw.len();
        }
        if raw.len() > 65_536 {
            anyhow::bail!("HTTP headers too large");
        }
    };

    let header_str = std::str::from_utf8(&raw[..header_end])?;
    let mut lines = header_str.lines();

    // Request line
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.splitn(3, ' ');
    let method = parts.next().unwrap_or("POST").to_string();
    let path = parts.next().unwrap_or("/").to_string();

    // Headers
    let mut headers = HashMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_lowercase();
            if key == "content-length" && headers.contains_key(&key) {
                anyhow::bail!("duplicate Content-Length header");
            }
            headers.insert(key, v.trim().to_string());
        }
    }
    if headers.contains_key("transfer-encoding") {
        anyhow::bail!("Transfer-Encoding is not supported");
    }

    // Body. Bound the declared length BEFORE allocating: the gateway listens on
    // 0.0.0.0 and (unless mTLS is enabled) is unauthenticated, so an attacker-set
    // `Content-Length` must never drive an unbounded allocation. Mirrors the UDS
    // wire protocol's MAX_PAYLOAD_LEN cap (JG-RT-001).
    let content_length: usize = match headers.get("content-length") {
        Some(raw) => raw
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid Content-Length header"))?,
        None => 0,
    };
    if content_length > MAX_MCP_BODY_BYTES {
        anyhow::bail!(
            "declared Content-Length {content_length} exceeds limit {MAX_MCP_BODY_BYTES}"
        );
    }
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        stream.read_exact(&mut body).await?;
    }

    Ok(HttpRequest {
        method,
        path,
        headers,
        body,
    })
}

/// Write a minimal HTTP/1.1 response.
async fn write_http_response<S: AsyncWrite + Unpin>(
    stream: &mut S,
    status: u16,
    status_text: &str,
    content_type: &str,
    body: &[u8],
) -> std::io::Result<()> {
    let header = format!(
        "HTTP/1.1 {status} {status_text}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        body.len()
    );
    stream.write_all(header.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await
}

// ---------------------------------------------------------------------------
// Per-connection handler
// ---------------------------------------------------------------------------

/// Handle a single incoming MCP gateway TCP connection.
// A connection handler legitimately needs the full request context (transport,
// peer, policy, registry, audit, telemetry, secret, upstream); bundling these
// into a struct would not improve clarity.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_mcp_connection<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    peer_addr: SocketAddr,
    current_policy: PolicyConfig,
    registry_store: Arc<Mutex<LineageRegistry>>,
    audit_logger: Arc<AuditLogger>,
    telemetry_store: TelemetryStore,
    secret: Arc<Vec<u8>>,
    upstream_addr: String,
) {
    // Read the incoming HTTP request.
    let http_req = match timeout(MCP_REQUEST_READ_TIMEOUT, read_http_request(&mut stream)).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            eprintln!("[mcp_gateway] failed to read HTTP request from {peer_addr}: {e}");
            let _ = write_http_response(
                &mut stream,
                400,
                "Bad Request",
                "text/plain",
                b"Bad Request",
            )
            .await;
            return;
        }
        Err(_) => {
            eprintln!("[mcp_gateway] timed out reading HTTP request from {peer_addr}");
            let _ = write_http_response(
                &mut stream,
                408,
                "Request Timeout",
                "text/plain",
                b"Request Timeout",
            )
            .await;
            return;
        }
    };

    // Parse JSON-RPC body.
    let jsonrpc: JsonRpcRequest = match serde_json::from_slice(&http_req.body) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[mcp_gateway] JSON-RPC parse error from {peer_addr}: {e}");
            let body = serde_json::to_vec(&JsonRpcError {
                jsonrpc: "2.0",
                id: Value::Null,
                error: JsonRpcErrorObj {
                    code: -32700,
                    message: format!("Parse error: {e}"),
                    data: None,
                },
            })
            .unwrap_or_default();
            let _ = write_http_response(&mut stream, 400, "Bad Request", "application/json", &body)
                .await;
            return;
        }
    };

    // Derive synthetic agent_id from client IP + HMAC secret.
    let peer_ip = peer_addr.ip().to_string();
    let agent_id = synthetic_agent_id(&peer_ip, secret.as_slice());

    // Map JSON-RPC params to context_vars.
    let mut context_vars: HashMap<String, f64> = HashMap::new();
    if let Some(obj) = jsonrpc.params.as_object() {
        for (k, v) in obj {
            if let Some(n) = v.as_f64() {
                context_vars.insert(k.clone(), n);
            }
        }
    }

    // Extract special fields from params before mapping to context_vars.
    let action_risk_score: Option<f64> = jsonrpc
        .params
        .as_object()
        .and_then(|obj| obj.get("action_risk_score"))
        .and_then(|v| v.as_f64());

    // Build a synthetic sequence counter from the current timestamp.
    let seq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let proposal = ClientProposal {
        sequence_counter: seq,
        intent_name: Some(jsonrpc.method.clone()),
        context_vars,
        session_privilege_bit: None,
        action_risk_score,
        prompt: None,
        plan: None,
        source_code: None,
        requested_capabilities: vec![],
        proposed_action: None,
    };

    // Use dummy PID/UID/GID (0) for MCP connections — no SO_PEERCRED available over TCP.
    let observation = ObservationRecord::from_peer(0, 0, 0);
    let lineage_key = format!("mcp:{}", agent_id);

    if system_immunity::mcp_caller_is_immune(&jsonrpc.method, &jsonrpc.params) {
        let reason = "system_process_immunity";
        let assessment = mcp_immunity_assessment(reason);
        let semantic_intent = mcp_immunity_intent(&jsonrpc.method, reason);
        let decision = PolicyDecision::allow(&assessment);
        let _ = audit_logger.log(&observation, &semantic_intent, &assessment, &decision);
        println!(
            "[mcp_gateway] ALLOW peer={peer_ip} method={} reason={reason} → forwarding to {upstream_addr}",
            jsonrpc.method
        );
        emit_mcp_decision_explanation(
            "ALLOW",
            reason,
            &peer_ip,
            &jsonrpc.method,
            &agent_id,
            &assessment,
        );

        match forward_to_upstream(
            &upstream_addr,
            &http_req.method,
            &http_req.path,
            &http_req.headers,
            &http_req.body,
        )
        .await
        {
            Ok((status, status_text, body)) => {
                let _ = write_http_response(
                    &mut stream,
                    status,
                    &status_text,
                    "application/json",
                    &body,
                )
                .await;
            }
            Err(e) => {
                eprintln!("[mcp_gateway] upstream error after immunity allow: {e}");
                let body = serde_json::to_vec(&serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": jsonrpc.id,
                    "error": { "code": -32603, "message": format!("Upstream error: {e}") }
                }))
                .unwrap_or_default();
                let _ =
                    write_http_response(&mut stream, 502, "Bad Gateway", "application/json", &body)
                        .await;
            }
        }
        return;
    }

    let enforcement_path = mcp_enforcement_path(&jsonrpc.params);
    if let Some(reason) = explicit_protected_resource_attack(
        Some(&jsonrpc.method),
        None,
        Some(&jsonrpc.params),
        enforcement_path,
    ) {
        println!(
            "[mcp_gateway] DENY peer={peer_ip} method={} reason={reason}",
            jsonrpc.method
        );
        let assessment = RiskAssessment {
            observed_risk: 0.0,
            semantic_risk: 99.0,
            topology_risk: 0.0,
            declared_risk: action_risk_score,
            fused_risk: action_risk_score.unwrap_or(99.0).max(99.0),
            trust_score: 1.0,
            reasons: vec![reason.to_string()],
        };
        emit_mcp_decision_explanation(
            "DENY",
            reason,
            &peer_ip,
            &jsonrpc.method,
            &agent_id,
            &assessment,
        );
        let body = serde_json::to_vec(&serde_json::json!({
            "signal": "DENY_PROTECTED_RESOURCE_ACTION",
            "reason": reason,
            "risk_score": assessment.fused_risk,
            "jsonrpc": "2.0",
            "id": jsonrpc.id,
            "error": {
                "code": -32600,
                "message": "Request denied by Jinn Guard: protected resource action",
            }
        }))
        .unwrap_or_default();
        let _ = write_http_response(&mut stream, 403, "Forbidden", "application/json", &body).await;
        return;
    }

    let constrain_floor = current_policy.upper_safety_boundary * 0.40;
    let force_policy = mcp_requires_intent_aware_enforcement(
        &jsonrpc.method,
        &jsonrpc.params,
        enforcement_path,
        action_risk_score,
        constrain_floor,
    );
    if let Some(enforcement_path) = enforcement_path {
        if !is_enforcement_target(enforcement_path) && !force_policy {
            let reason = "outside_enforcement_scope";
            let assessment = mcp_immunity_assessment(reason);
            let semantic_intent = mcp_immunity_intent(&jsonrpc.method, reason);
            let decision = PolicyDecision::allow(&assessment);
            let _ = audit_logger.log(&observation, &semantic_intent, &assessment, &decision);
            println!(
                "[mcp_gateway] ALLOW peer={peer_ip} method={} path={} reason={reason} → forwarding to {upstream_addr}",
                jsonrpc.method, enforcement_path
            );
            emit_mcp_decision_explanation(
                "ALLOW",
                reason,
                &peer_ip,
                &jsonrpc.method,
                &agent_id,
                &assessment,
            );

            match forward_to_upstream(
                &upstream_addr,
                &http_req.method,
                &http_req.path,
                &http_req.headers,
                &http_req.body,
            )
            .await
            {
                Ok((status, status_text, body)) => {
                    let _ = write_http_response(
                        &mut stream,
                        status,
                        &status_text,
                        "application/json",
                        &body,
                    )
                    .await;
                }
                Err(e) => {
                    eprintln!("[mcp_gateway] upstream error after outside-scope allow: {e}");
                    let body = serde_json::to_vec(&serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": jsonrpc.id,
                        "error": { "code": -32603, "message": format!("Upstream error: {e}") }
                    }))
                    .unwrap_or_default();
                    let _ = write_http_response(
                        &mut stream,
                        502,
                        "Bad Gateway",
                        "application/json",
                        &body,
                    )
                    .await;
                }
            }
            return;
        }
    }

    // Prune dead processes.
    {
        let mut reg = registry_store.lock().unwrap();
        reg.prune_dead_processes();
    }

    // Snapshot eBPF telemetry for PID 0 (none expected for MCP connections).
    let peer_telemetry: Vec<KernelTelemetryEvent> = {
        let mut store = telemetry_store.lock().unwrap();
        store.remove(&0).unwrap_or_default()
    };

    // ── deny_anonymous check ─────────────────────────────────────────────
    // MCP connections always have a synthetic agent_id, so this won't fire
    // unless the policy node lookup fails.

    // ── Policy node lookup ───────────────────────────────────────────────
    // MCP gateway agents are not required to be in agent_nodes; if absent, they
    // proceed with an anonymous/low-privilege risk profile.

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

    // Apply any eBPF telemetry penalty.
    if !peer_telemetry.is_empty() {
        let penalty = observed_risk_penalty(&peer_telemetry);
        if penalty > 0.0 {
            assessment.observed_risk = (assessment.observed_risk + penalty).min(99.0);
            assessment.fused_risk = (assessment.observed_risk * 0.40
                + assessment.semantic_risk * 0.35
                + assessment.topology_risk * 0.25)
                .min(99.0);
        }
    }

    // ── Lineage tracking ─────────────────────────────────────────────────
    let lineage_ok = {
        let mut reg = registry_store.lock().unwrap();
        let lineage = reg
            .data
            .lineages
            .entry(lineage_key.clone())
            .or_insert_with(|| AgentLineage::new(&observation, seq, &assessment));
        if lineage.validate_sequence(seq).is_err() {
            false // sequence replay — tolerated for TCP (no strict ordering required)
        } else {
            lineage.record(&observation, seq, &assessment);
            let _ = reg.save();
            true
        }
    };
    let _ = lineage_ok; // MCP gateway is lenient on sequence ordering

    // ── Policy decision ──────────────────────────────────────────────────
    let decision = policy_decision(&assessment, &current_policy);
    let _ = audit_logger.log(&observation, &semantic_intent, &assessment, &decision);

    if !decision.is_allow() {
        println!(
            "[mcp_gateway] DENY peer={peer_ip} method={} risk={:.2} reason={}",
            jsonrpc.method, assessment.fused_risk, decision.reason
        );
        emit_mcp_decision_explanation(
            "DENY",
            &decision.reason,
            &peer_ip,
            &jsonrpc.method,
            &agent_id,
            &assessment,
        );
        // Return HTTP 403 with deny signal as JSON body.
        let body = serde_json::to_vec(&serde_json::json!({
            "signal": format!("DENY_{}", decision.reason.to_uppercase()),
            "reason": decision.reason,
            "risk_score": assessment.fused_risk,
            "jsonrpc": "2.0",
            "id": jsonrpc.id,
            "error": {
                "code": -32600,
                "message": format!("Request denied by Jinn Guard: {}", decision.reason),
            }
        }))
        .unwrap_or_default();
        let _ = write_http_response(&mut stream, 403, "Forbidden", "application/json", &body).await;
        return;
    }

    // ── Execution broker ─────────────────────────────────────────────────
    let exec_req = ExecutionRequest {
        action: crate::governance::ProposedAction::ShellCommand {
            command: format!("echo 'mcp_proxy:{}'", jsonrpc.method),
        },
        observation: observation.clone(),
        semantic_intent: semantic_intent.clone(),
        risk_assessment: assessment.clone(),
        policy_decision: decision.clone(),
    };
    let exec_decision = ExecutionBroker.decide(exec_req);
    if !exec_decision.permitted {
        println!(
            "[mcp_gateway] DENY_BROKER peer={peer_ip} method={} reason={}",
            jsonrpc.method, exec_decision.reason
        );
        emit_mcp_decision_explanation(
            "DENY",
            &exec_decision.reason,
            &peer_ip,
            &jsonrpc.method,
            &agent_id,
            &assessment,
        );
        let body = serde_json::to_vec(&serde_json::json!({
            "signal": "DENY_EXECUTION_BROKER",
            "reason": exec_decision.reason,
            "jsonrpc": "2.0",
            "id": jsonrpc.id,
            "error": { "code": -32600, "message": exec_decision.reason }
        }))
        .unwrap_or_default();
        let _ = write_http_response(&mut stream, 403, "Forbidden", "application/json", &body).await;
        return;
    }

    println!(
        "[mcp_gateway] ALLOW peer={peer_ip} method={} risk={:.2} → forwarding to {upstream_addr}",
        jsonrpc.method, assessment.fused_risk
    );
    emit_mcp_decision_explanation(
        "ALLOW",
        &decision.reason,
        &peer_ip,
        &jsonrpc.method,
        &agent_id,
        &assessment,
    );

    // ── Forward to upstream ──────────────────────────────────────────────
    let upstream_resp = forward_to_upstream(
        &upstream_addr,
        &http_req.method,
        &http_req.path,
        &http_req.headers,
        &http_req.body,
    )
    .await;

    match upstream_resp {
        Ok((status, status_text, body)) => {
            // Apply output byte limit if constrained.
            let body = {
                if let Some(limit) = exec_decision
                    .active_constraints
                    .as_ref()
                    .and_then(|c| c.output_byte_limit)
                {
                    if body.len() > limit {
                        let truncated = serde_json::json!({
                            "truncated": true,
                            "bytes_limit": limit,
                            "output": String::from_utf8_lossy(&body[..limit])
                        });
                        serde_json::to_vec(&truncated).unwrap_or(body[..limit].to_vec())
                    } else {
                        body
                    }
                } else {
                    body
                }
            };
            let _ =
                write_http_response(&mut stream, status, &status_text, "application/json", &body)
                    .await;
        }
        Err(e) => {
            eprintln!("[mcp_gateway] upstream error: {e}");
            let body = serde_json::to_vec(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": jsonrpc.id,
                "error": { "code": -32603, "message": format!("Upstream error: {e}") }
            }))
            .unwrap_or_default();
            let _ = write_http_response(&mut stream, 502, "Bad Gateway", "application/json", &body)
                .await;
        }
    }
}

/// Forward the request to the upstream MCP server using a raw TCP connection.
/// Returns (status_code, status_text, body_bytes).
async fn forward_to_upstream(
    upstream_addr: &str,
    method: &str,
    path: &str,
    original_headers: &HashMap<String, String>,
    body: &[u8],
) -> anyhow::Result<(u16, String, Vec<u8>)> {
    // Defense-in-depth (JG-RT-003): the request line/headers we send upstream are
    // built from client-controlled `method`, `path` and `Host`. Refuse any control
    // character (CR/LF/NUL) so a crafted value can never inject a header or smuggle
    // a second request into the upstream connection, independent of the inbound
    // parser's line handling.
    let host = original_headers
        .get("host")
        .cloned()
        .unwrap_or_else(|| upstream_addr.to_string());
    for (field, value) in [("method", method), ("path", path), ("host", host.as_str())] {
        if value.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0) {
            anyhow::bail!("refusing to forward: control character in request {field}");
        }
    }

    let mut upstream = timeout(
        MCP_UPSTREAM_CONNECT_TIMEOUT,
        TcpStream::connect(upstream_addr),
    )
    .await
    .map_err(|_| anyhow::anyhow!("upstream connect timed out"))?
    .map_err(|e| anyhow::anyhow!("upstream connect failed: {e}"))?;

    // Build minimal HTTP/1.1 request.
    let request = format!(
        "{method} {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        body.len()
    );
    upstream.write_all(request.as_bytes()).await?;
    upstream.write_all(body).await?;
    upstream.flush().await?;

    // Read a bounded response. The upstream is operator-configured, but this
    // still must not become an unbounded allocation sink if that process is
    // compromised or misconfigured.
    let raw = timeout(
        MCP_UPSTREAM_RESPONSE_TIMEOUT,
        read_limited_to_end(&mut upstream, MAX_MCP_UPSTREAM_RESPONSE_BYTES),
    )
    .await
    .map_err(|_| anyhow::anyhow!("upstream response timed out"))??;

    // Parse the status line.
    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or(raw.len());
    let header_str = std::str::from_utf8(&raw[..header_end]).unwrap_or("");
    let mut lines = header_str.lines();
    let status_line = lines.next().unwrap_or("HTTP/1.1 200 OK");
    let mut parts = status_line.splitn(3, ' ');
    let _ = parts.next(); // HTTP/1.1
    let status: u16 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(200);
    let status_text = parts.next().unwrap_or("OK").to_string();

    let resp_body = if header_end + 4 < raw.len() {
        raw[header_end + 4..].to_vec()
    } else {
        vec![]
    };

    Ok((status, status_text, resp_body))
}

async fn read_limited_to_end<S: AsyncRead + Unpin>(
    stream: &mut S,
    limit: usize,
) -> anyhow::Result<Vec<u8>> {
    let mut raw = Vec::with_capacity(4096);
    let mut buf = [0u8; 8192];
    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            return Ok(raw);
        }
        if raw.len().saturating_add(n) > limit {
            anyhow::bail!("upstream response exceeds limit {limit} bytes");
        }
        raw.extend_from_slice(&buf[..n]);
    }
}

// ---------------------------------------------------------------------------
// Public entry point — called from main.rs to start the gateway listener.
// ---------------------------------------------------------------------------

/// Operator-supplied mTLS material for the MCP gateway (#11). All three are
/// required together: a server identity (`cert` + `key`) the gateway presents, and
/// the `ca` used to verify connecting clients.
#[derive(Debug, Clone)]
pub(crate) struct McpTlsConfig {
    pub cert: String,
    pub key: String,
    pub ca: String,
}

/// Build an mTLS `SslAcceptor` that presents `cert`/`key` and **requires** a client
/// certificate chaining to `ca`. A client presenting no certificate — or one not
/// signed by `ca` — fails the handshake, so an unauthenticated MCP client never
/// reaches the governance pipeline (fail-closed). Errors if any file is missing or
/// the private key does not match the certificate.
pub(crate) fn build_mcp_tls_acceptor(cfg: &McpTlsConfig) -> anyhow::Result<SslAcceptor> {
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())
        .map_err(|e| anyhow::anyhow!("mcp mTLS: cannot init acceptor: {e}"))?;
    builder
        .set_certificate_chain_file(&cfg.cert)
        .map_err(|e| anyhow::anyhow!("mcp mTLS: bad server cert {}: {e}", cfg.cert))?;
    builder
        .set_private_key_file(&cfg.key, SslFiletype::PEM)
        .map_err(|e| anyhow::anyhow!("mcp mTLS: bad server key {}: {e}", cfg.key))?;
    builder
        .check_private_key()
        .map_err(|e| anyhow::anyhow!("mcp mTLS: private key does not match certificate: {e}"))?;
    builder
        .set_ca_file(&cfg.ca)
        .map_err(|e| anyhow::anyhow!("mcp mTLS: bad client CA {}: {e}", cfg.ca))?;
    // The "mutual" in mTLS: require AND verify the client certificate.
    builder.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
    Ok(builder.build())
}

/// Complete the server-side TLS handshake (verifying the client certificate) and
/// return the encrypted stream.
async fn accept_tls(
    acceptor: &SslAcceptor,
    stream: TcpStream,
) -> anyhow::Result<tokio_openssl::SslStream<TcpStream>> {
    let ssl = openssl::ssl::Ssl::new(acceptor.context())?;
    let mut tls = tokio_openssl::SslStream::new(ssl, stream)?;
    std::pin::Pin::new(&mut tls).accept().await?;
    Ok(tls)
}

// The gateway runner threads the full request context plus the optional TLS
// acceptor; bundling these into a struct would not improve clarity.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_mcp_gateway(
    port: u16,
    upstream: String,
    active_policy: Arc<Mutex<crate::PolicyConfig>>,
    registry_store: Arc<Mutex<LineageRegistry>>,
    audit_logger: Arc<AuditLogger>,
    telemetry_store: TelemetryStore,
    secret: Arc<Vec<u8>>,
    tls: Option<Arc<SslAcceptor>>,
) {
    let addr = format!("0.0.0.0:{port}");
    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(l) => {
            let mode = if tls.is_some() { "mTLS" } else { "plaintext" };
            println!("[MCP] gateway listening on {addr} ({mode})");
            l
        }
        Err(e) => {
            eprintln!("[MCP] failed to bind gateway on {addr}: {e}");
            return;
        }
    };

    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                let policy_snapshot = active_policy.lock().unwrap().clone();
                let registry_clone = Arc::clone(&registry_store);
                let logger_clone = Arc::clone(&audit_logger);
                let telemetry_clone = Arc::clone(&telemetry_store);
                let upstream_clone = upstream.clone();
                let secret_clone = Arc::clone(&secret);
                let tls_clone = tls.clone();

                tokio::spawn(async move {
                    let worker = tokio::spawn(async move {
                        // With mTLS configured, complete (and verify) the handshake
                        // before the connection reaches the governance pipeline; a
                        // failed handshake drops the connection fail-closed.
                        match tls_clone {
                            Some(acceptor) => match accept_tls(&acceptor, stream).await {
                                Ok(tls_stream) => {
                                    handle_mcp_connection(
                                        tls_stream,
                                        peer_addr,
                                        policy_snapshot,
                                        registry_clone,
                                        logger_clone,
                                        telemetry_clone,
                                        secret_clone,
                                        upstream_clone,
                                    )
                                    .await;
                                }
                                Err(e) => {
                                    eprintln!("[MCP] mTLS handshake rejected from {peer_addr}: {e}")
                                }
                            },
                            None => {
                                handle_mcp_connection(
                                    stream,
                                    peer_addr,
                                    policy_snapshot,
                                    registry_clone,
                                    logger_clone,
                                    telemetry_clone,
                                    secret_clone,
                                    upstream_clone,
                                )
                                .await;
                            }
                        }
                    });

                    if let Err(err) = worker.await {
                        eprintln!(
                            "[mcp_gateway] isolated connection task failure from {peer_addr}: {err}"
                        );
                    }
                });
            }
            Err(e) => eprintln!("[MCP] accept error: {e}"),
        }
    }
}

#[cfg(test)]
mod mcp_gateway_tests {
    use super::*;
    use openssl::asn1::Asn1Time;
    use openssl::hash::MessageDigest;
    use openssl::pkey::{PKey, Private};
    use openssl::rsa::Rsa;
    use openssl::x509::{X509NameBuilder, X509};
    use std::io::Write;

    /// Generate a throwaway self-signed cert + key for the acceptor tests.
    fn self_signed(cn: &str) -> (PKey<Private>, X509) {
        let pkey = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", cn).unwrap();
        let name = name.build();
        let mut b = X509::builder().unwrap();
        b.set_version(2).unwrap();
        b.set_subject_name(&name).unwrap();
        b.set_issuer_name(&name).unwrap();
        b.set_pubkey(&pkey).unwrap();
        b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        b.set_not_after(&Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        b.sign(&pkey, MessageDigest::sha256()).unwrap();
        (pkey, b.build())
    }

    fn write_temp(name: &str, bytes: &[u8]) -> String {
        let path = std::env::temp_dir().join(format!("jg_mtls_test_{name}"));
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(bytes).unwrap();
        path.to_string_lossy().into_owned()
    }

    #[test]
    fn acceptor_builds_from_valid_material() {
        let (key, cert) = self_signed("jinnguard-mcp");
        let cert_path = write_temp("ok.crt", &cert.to_pem().unwrap());
        let key_path = write_temp("ok.key", &key.private_key_to_pem_pkcs8().unwrap());
        // The same self-signed cert doubles as the client-trust CA here.
        let cfg = McpTlsConfig {
            cert: cert_path.clone(),
            key: key_path.clone(),
            ca: cert_path.clone(),
        };
        assert!(
            build_mcp_tls_acceptor(&cfg).is_ok(),
            "valid cert/key/ca must build an acceptor"
        );
        for p in [cert_path, key_path] {
            let _ = std::fs::remove_file(p);
        }
    }

    #[test]
    fn acceptor_rejects_missing_files() {
        let cfg = McpTlsConfig {
            cert: "/nonexistent/jg/server.crt".to_string(),
            key: "/nonexistent/jg/server.key".to_string(),
            ca: "/nonexistent/jg/ca.crt".to_string(),
        };
        assert!(
            build_mcp_tls_acceptor(&cfg).is_err(),
            "missing material must fail closed, not build a usable acceptor"
        );
    }

    #[test]
    fn acceptor_rejects_mismatched_key_and_cert() {
        // A cert from one keypair with the private key of another must be refused.
        let (_k1, cert1) = self_signed("server-a");
        let (k2, _c2) = self_signed("server-b");
        let cert_path = write_temp("mismatch.crt", &cert1.to_pem().unwrap());
        let key_path = write_temp("mismatch.key", &k2.private_key_to_pem_pkcs8().unwrap());
        let cfg = McpTlsConfig {
            cert: cert_path.clone(),
            key: key_path.clone(),
            ca: cert_path.clone(),
        };
        assert!(
            build_mcp_tls_acceptor(&cfg).is_err(),
            "a private key that does not match the cert must be rejected"
        );
        for p in [cert_path, key_path] {
            let _ = std::fs::remove_file(p);
        }
    }

    // JG-RT-001: an attacker-controlled Content-Length must not drive allocation.
    #[tokio::test]
    async fn rejects_oversized_content_length_before_allocating() {
        let req = format!(
            "POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
            MAX_MCP_BODY_BYTES + 1
        );
        let mut input: &[u8] = req.as_bytes();
        let result = read_http_request(&mut input).await;
        assert!(
            result.is_err(),
            "an over-limit Content-Length must be refused, not allocated"
        );
    }

    #[tokio::test]
    async fn rejects_duplicate_content_length() {
        let req = "POST / HTTP/1.1\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}";
        let mut input: &[u8] = req.as_bytes();
        let err = match read_http_request(&mut input).await {
            Ok(_) => panic!("duplicate Content-Length must be rejected"),
            Err(err) => err.to_string(),
        };
        assert!(err.contains("duplicate Content-Length"), "got: {err}");
    }

    #[tokio::test]
    async fn rejects_transfer_encoding() {
        let req = "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n";
        let mut input: &[u8] = req.as_bytes();
        let err = match read_http_request(&mut input).await {
            Ok(_) => panic!("Transfer-Encoding must be rejected"),
            Err(err) => err.to_string(),
        };
        assert!(err.contains("Transfer-Encoding"), "got: {err}");
    }

    // JG-RT-003: a control character in client-derived method/path/Host must be
    // refused before anything is written upstream (the guard runs before connect,
    // so no live upstream is needed to exercise it).
    #[tokio::test]
    async fn refuses_to_forward_crlf_in_request_line() {
        let headers = HashMap::new();
        let err = forward_to_upstream("127.0.0.1:1", "GET", "/x\r\nEvil: 1", &headers, b"")
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("control character"), "got: {err}");

        let mut bad_host = HashMap::new();
        bad_host.insert("host".to_string(), "h\r\nX-Smuggle: 1".to_string());
        let err = forward_to_upstream("127.0.0.1:1", "GET", "/", &bad_host, b"")
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("control character"), "got: {err}");
    }

    #[tokio::test]
    async fn parses_request_within_body_limit() {
        let body = b"{\"jsonrpc\":\"2.0\"}";
        let req = format!(
            "POST /rpc HTTP/1.1\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            std::str::from_utf8(body).unwrap()
        );
        let mut input: &[u8] = req.as_bytes();
        let parsed = read_http_request(&mut input)
            .await
            .expect("valid request parses");
        assert_eq!(parsed.method, "POST");
        assert_eq!(parsed.path, "/rpc");
        assert_eq!(parsed.body, body);
    }

    #[tokio::test]
    async fn upstream_response_read_is_bounded() {
        let mut input: &[u8] = b"HTTP/1.1 200 OK\r\n\r\n0123456789";
        let err = read_limited_to_end(&mut input, 8)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("upstream response exceeds limit"),
            "got: {err}"
        );
    }
}
