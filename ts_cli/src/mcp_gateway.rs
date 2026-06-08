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
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::{
    get_runtime_secret,
    governance::{
        AgentLineage, AuditLogger, CapabilityProfile, ClientProposal, CombinedSemanticService,
        ExecutionBroker, ExecutionRequest, LineageRegistry, ObservationRecord, RiskAssessment,
        SemanticAnalysisService,
    },
    observed_risk_penalty, policy_decision, KernelTelemetryEvent, PolicyConfig, TelemetryStore,
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

// ---------------------------------------------------------------------------
// HTTP/1.1 minimal parser
// ---------------------------------------------------------------------------

struct HttpRequest {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

/// Read a minimal HTTP/1.1 request from a tokio TcpStream.
/// Supports chunked detection but does not decode chunks — the body is read
/// by Content-Length only, which is the norm for JSON-RPC clients.
async fn read_http_request(stream: &mut TcpStream) -> anyhow::Result<HttpRequest> {
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
            headers.insert(k.trim().to_lowercase(), v.trim().to_string());
        }
    }

    // Body
    let content_length: usize = headers
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
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
async fn write_http_response(
    stream: &mut TcpStream,
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
pub(crate) async fn handle_mcp_connection(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    current_policy: PolicyConfig,
    registry_store: Arc<Mutex<LineageRegistry>>,
    audit_logger: Arc<AuditLogger>,
    telemetry_store: TelemetryStore,
    secret_file: Option<String>,
    upstream_addr: String,
) {
    // Read the incoming HTTP request.
    let http_req = match read_http_request(&mut stream).await {
        Ok(r) => r,
        Err(e) => {
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
    let secret_bytes: Vec<u8> = match &secret_file {
        Some(path) => std::fs::read(path).unwrap_or_default(),
        None => get_runtime_secret().unwrap_or_default(),
    };
    let agent_id = synthetic_agent_id(&peer_ip, &secret_bytes);

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
    let mut upstream = TcpStream::connect(upstream_addr)
        .await
        .map_err(|e| anyhow::anyhow!("upstream connect failed: {e}"))?;

    // Build minimal HTTP/1.1 request.
    let host = original_headers
        .get("host")
        .cloned()
        .unwrap_or_else(|| upstream_addr.to_string());
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

    // Read the full response.
    let mut raw = Vec::with_capacity(4096);
    upstream.read_to_end(&mut raw).await?;

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

// ---------------------------------------------------------------------------
// Public entry point — called from main.rs to start the gateway listener.
// ---------------------------------------------------------------------------

pub(crate) async fn run_mcp_gateway(
    port: u16,
    upstream: String,
    active_policy: Arc<Mutex<crate::PolicyConfig>>,
    registry_store: Arc<Mutex<LineageRegistry>>,
    audit_logger: Arc<AuditLogger>,
    telemetry_store: TelemetryStore,
    secret: Arc<Vec<u8>>,
) {
    let addr = format!("0.0.0.0:{port}");
    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(l) => {
            println!("[MCP] gateway listening on {addr}");
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

                tokio::spawn(async move {
                    handle_mcp_connection(
                        stream,
                        peer_addr,
                        policy_snapshot,
                        registry_clone,
                        logger_clone,
                        telemetry_clone,
                        None,           // secret_file — use env var / runtime secret
                        upstream_clone, // upstream_addr
                    )
                    .await;
                });
            }
            Err(e) => eprintln!("[MCP] accept error: {e}"),
        }
    }
}
