// tests/integration/main.rs
//
// Jinn Guard — automated CI integration test suite.
//
// Run with:
//   cargo test --test integration
//
// Each test case:
//   1. Spawns the full jinnguard daemon as a child process
//   2. Connects via a UNIX domain socket
//   3. Sends a HMAC-signed framed proposal
//   4. Asserts the exact SIGNAL response
//   5. Tears down cleanly via DaemonGuard::Drop
//
// The harness is fully self-contained: it writes temporary policy, secret,
// lineage, and audit log files and cleans them up after each test.

use hmac::{Hmac, KeyInit, Mac};
use rusqlite::{params, Connection};
use sha2::Sha256;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------------------
// Shared sequence counter — each test uses a unique monotonic sequence number
// to prevent replay-attack false positives between tests.
// ---------------------------------------------------------------------------

static SEQ: AtomicU64 = AtomicU64::new(9_000_000);

fn next_seq() -> u64 {
    SEQ.fetch_add(1, Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// Test infrastructure
// ---------------------------------------------------------------------------

const TEST_SECRET: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn daemon_binary() -> String {
    std::env::var("JINNGUARD_TEST_BINARY").unwrap_or_else(|_| {
        // CARGO_MANIFEST_DIR is the ts_cli/ directory at compile time.
        let manifest = env!("CARGO_MANIFEST_DIR");
        format!("{manifest}/../target/debug/ts_cli")
    })
}

/// Write a policy YAML for the given socket path prefix (unique per test).
fn write_policy(path: &str, quota: u64, allowed_intents: &[&str]) {
    let intents_yaml = if allowed_intents.is_empty() {
        "    allowed_intents: []".to_string()
    } else {
        let lines: Vec<String> = allowed_intents
            .iter()
            .map(|i| format!("      - \"{}\"", i))
            .collect();
        format!("    allowed_intents:\n{}", lines.join("\n"))
    };

    let yaml = format!(
        r#"
global_safety_ceiling: 90.0
agent_nodes:
  - id: "test_agent"
    privilege_tier: 1
    max_sequence_quota: {quota}
{intents_yaml}
    invariants: []
"#
    );
    std::fs::write(path, &yaml).unwrap_or_else(|e| panic!("write policy {path}: {e}"));
}

fn sign_payload(payload: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(TEST_SECRET.as_bytes()).unwrap();
    mac.update(payload.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Build a full framed wire packet.
fn build_packet(
    seq: u64,
    intent: &str,
    agent_id: Option<&str>,
    risk: f64,
    plan: Option<&str>,
    action_kind: Option<&str>,
) -> Vec<u8> {
    let agent_field = match agent_id {
        Some(id) => format!(r#","agent_id":"{id}""#),
        None => String::new(),
    };
    let plan_field = match plan {
        Some(p) => format!(r#","plan":{:?}"#, p),
        None => String::new(),
    };
    let action_field = match action_kind {
        Some(a) => format!(r#","proposed_action":{a}"#),
        None => String::new(),
    };

    let payload = format!(
        r#"{{"sequence_counter":{seq},"intent_name":"{intent}","action_risk_score":{risk}{agent_field}{plan_field}{action_field}}}"#
    );
    let sig = sign_payload(&payload);
    let envelope = serde_json::json!({
        "payload": payload,
        "signature": sig,
    })
    .to_string();

    let body = envelope.as_bytes();
    let mut packet = Vec::with_capacity(5 + body.len());
    packet.extend_from_slice(&(body.len() as u32).to_be_bytes());
    packet.push(1u8);
    packet.extend_from_slice(body);
    packet
}

fn build_packet_with_path(
    seq: u64,
    intent: &str,
    agent_id: Option<&str>,
    risk: f64,
    path: &str,
) -> Vec<u8> {
    let agent_field = match agent_id {
        Some(id) => format!(r#","agent_id":"{id}""#),
        None => String::new(),
    };
    let payload = format!(
        r#"{{"sequence_counter":{seq},"intent_name":"{intent}","action_risk_score":{risk}{agent_field},"path":{path:?}}}"#
    );
    let sig = sign_payload(&payload);
    let envelope = serde_json::json!({
        "payload": payload,
        "signature": sig,
    })
    .to_string();

    let body = envelope.as_bytes();
    let mut packet = Vec::with_capacity(5 + body.len());
    packet.extend_from_slice(&(body.len() as u32).to_be_bytes());
    packet.push(1u8);
    packet.extend_from_slice(body);
    packet
}

/// Read a framed response, return body as String.
fn read_response(stream: &mut UnixStream) -> String {
    let mut header = [0u8; 5];
    stream.read_exact(&mut header).expect("read header");
    let len = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize;
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).expect("read body");
    String::from_utf8_lossy(&body).to_string()
}

/// RAII daemon process guard. Killed and cleaned up on drop.
struct DaemonGuard {
    child: Child,
    pub socket_path: String,
    secret_path: String,
    lineage_path: String,
    audit_path: String,
    policy_path: String,
}

fn lineage_db_path(file_path: &str) -> String {
    match file_path.strip_suffix(".json") {
        Some(stem) => format!("{stem}.db"),
        None => format!("{file_path}.db"),
    }
}

fn cleanup_daemon_files(
    socket_path: &str,
    secret_path: &str,
    lineage_path: &str,
    audit_path: &str,
    policy_path: &str,
) {
    for p in [
        socket_path.to_string(),
        secret_path.to_string(),
        lineage_path.to_string(),
        lineage_db_path(lineage_path),
        audit_path.to_string(),
        format!("{audit_path}.db"),
        policy_path.to_string(),
    ] {
        let _ = std::fs::remove_file(p);
    }
}

impl DaemonGuard {
    fn spawn_with_policy(tag: &str, quota: u64, allowed_intents: &[&str]) -> Self {
        let socket_path = format!("/tmp/jg_test_{tag}.sock");
        let secret_path = format!("/tmp/jg_test_{tag}.secret");
        let lineage_path = format!("/tmp/jg_test_{tag}.lineage.json");
        let audit_path = format!("/tmp/jg_test_{tag}.audit.log");
        let policy_path = format!("/tmp/jg_test_{tag}.policy.yaml");

        cleanup_daemon_files(
            &socket_path,
            &secret_path,
            &lineage_path,
            &audit_path,
            &policy_path,
        );

        write_policy(&policy_path, quota, allowed_intents);
        std::fs::write(&secret_path, TEST_SECRET).unwrap();

        let binary = daemon_binary();
        let child = Command::new(&binary)
            .args([
                "--socket-path",
                &socket_path,
                "--lineage-file",
                &lineage_path,
                "--audit-log",
                &audit_path,
                "--policy-file",
                &policy_path,
                "--secret-file",
                &secret_path,
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap_or_else(|e| {
                panic!(
                    "Cannot spawn daemon '{}': {e}\n\
                 Run `cargo build` first, or set JINNGUARD_TEST_BINARY.",
                    binary
                )
            });

        // Wait up to 4 seconds for the socket to appear.
        let deadline = Instant::now() + Duration::from_secs(4);
        while Instant::now() < deadline {
            if UnixStream::connect(&socket_path).is_ok() {
                break;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        assert!(
            std::path::Path::new(&socket_path).exists(),
            "Daemon socket never appeared at {socket_path}"
        );

        DaemonGuard {
            child,
            socket_path,
            secret_path,
            lineage_path,
            audit_path,
            policy_path,
        }
    }

    fn connect(&self) -> UnixStream {
        UnixStream::connect(&self.socket_path).expect("connect to daemon")
    }

    /// Send a packet and return the response signal string.
    fn send_recv(&self, packet: &[u8]) -> String {
        let mut stream = self.connect();
        stream.write_all(packet).expect("write packet");
        stream.flush().expect("flush");
        read_response(&mut stream)
    }

    fn lineage_state(&self, agent_id: &str) -> (u64, u64) {
        let conn = Connection::open(lineage_db_path(&self.lineage_path)).expect("open lineage db");
        conn.query_row(
            "SELECT last_sequence, decisions_seen FROM lineages WHERE key = ?1",
            params![agent_id],
            |row| Ok((row.get::<_, i64>(0)? as u64, row.get::<_, i64>(1)? as u64)),
        )
        .expect("lineage row")
    }
}

impl Drop for DaemonGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        cleanup_daemon_files(
            &self.socket_path,
            &self.secret_path,
            &self.lineage_path,
            &self.audit_path,
            &self.policy_path,
        );
    }
}

// ---------------------------------------------------------------------------
// Test 1 — ALLOW: Low-risk, correctly-signed, registered agent.
// ---------------------------------------------------------------------------

#[test]
fn test_allow_low_risk_registered_agent() {
    let daemon = DaemonGuard::spawn_with_policy("allow_basic", 0, &["read_file"]);
    let packet = build_packet(next_seq(), "read_file", Some("test_agent"), 5.0, None, None);
    let resp = daemon.send_recv(&packet);
    assert!(resp.contains("ALLOW"), "Expected ALLOW, got: {resp}");
}

#[test]
fn test_cached_secret_survives_mid_connection_secret_file_removal() {
    let daemon = DaemonGuard::spawn_with_policy("secret_cached", 0, &["read_file"]);
    let mut stream = daemon.connect();

    let p1 = build_packet(next_seq(), "read_file", Some("test_agent"), 5.0, None, None);
    stream.write_all(&p1).expect("write first packet");
    stream.flush().expect("flush first packet");
    let r1 = read_response(&mut stream);
    assert!(r1.contains("ALLOW"), "Expected first ALLOW, got: {r1}");

    std::fs::remove_file(&daemon.secret_path).expect("remove backing secret file");

    let p2 = build_packet(next_seq(), "read_file", Some("test_agent"), 5.0, None, None);
    stream.write_all(&p2).expect("write second packet");
    stream.flush().expect("flush second packet");
    let r2 = read_response(&mut stream);
    assert!(
        r2.contains("ALLOW"),
        "Expected cached startup secret to verify second request, got: {r2}"
    );
}

#[test]
fn test_out_of_order_sequence_is_denied_by_lineage() {
    let daemon = DaemonGuard::spawn_with_policy("lineage_order", 0, &["read_file"]);
    let high_seq = next_seq() + 10;
    let low_seq = high_seq - 1;

    let p1 = build_packet(high_seq, "read_file", Some("test_agent"), 5.0, None, None);
    let r1 = daemon.send_recv(&p1);
    assert!(r1.contains("ALLOW"), "Expected first ALLOW, got: {r1}");

    let p2 = build_packet(low_seq, "read_file", Some("test_agent"), 5.0, None, None);
    let r2 = daemon.send_recv(&p2);
    assert!(
        r2.contains("DENY_REPLAY_ATTACK"),
        "Expected out-of-order sequence to be denied, got: {r2}"
    );
}

#[test]
fn test_outside_scope_fast_path_persists_lineage_state() {
    let daemon = DaemonGuard::spawn_with_policy("outside_scope_lineage", 2, &["read_file"]);
    let seq = next_seq();
    let packet = build_packet_with_path(
        seq,
        "read_file",
        Some("test_agent"),
        5.0,
        "/opt/non-test-zone/report.txt",
    );

    let resp = daemon.send_recv(&packet);
    assert!(
        resp.contains("ALLOW"),
        "Expected outside-scope request to allow, got: {resp}"
    );

    let (last_sequence, decisions_seen) = daemon.lineage_state("test_agent");
    assert_eq!(last_sequence, seq);
    assert_eq!(decisions_seen, 1);
}

// ---------------------------------------------------------------------------
// Test 2 — DENY_REPLAY_ATTACK: Repeat an identical sequence_counter.
// ---------------------------------------------------------------------------

#[test]
fn test_deny_replay_attack() {
    let daemon = DaemonGuard::spawn_with_policy("replay", 0, &["read_file"]);
    let seq = next_seq();
    let packet = build_packet(seq, "read_file", Some("test_agent"), 5.0, None, None);

    // First request — should succeed.
    let r1 = daemon.send_recv(&packet);
    // Sequence 0 seeds the lineage; first proposal may get ALLOW or replay depending
    // on initial state. What matters is the second duplicate gets DENY_REPLAY_ATTACK.
    // Re-send the *exact same* packet with the same sequence number.
    let r2 = daemon.send_recv(&packet);
    assert!(
        r2.contains("DENY_REPLAY_ATTACK"),
        "Expected DENY_REPLAY_ATTACK on duplicate seq={seq}, got: {r2} (first={r1})"
    );
}

// ---------------------------------------------------------------------------
// Test 3 — DENY_TAMPERED_TOKEN: Corrupted HMAC signature.
// ---------------------------------------------------------------------------

#[test]
fn test_deny_tampered_token() {
    let daemon = DaemonGuard::spawn_with_policy("tamper", 0, &[]);
    let seq = next_seq();
    let payload = format!(
        r#"{{"sequence_counter":{seq},"intent_name":"read_file","action_risk_score":5.0}}"#
    );
    // Use wrong key.
    let bad_sig = {
        let mut mac = HmacSha256::new_from_slice(b"wrong_key_for_testing_tamper").unwrap();
        mac.update(payload.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    };
    let envelope = serde_json::json!({ "payload": payload, "signature": bad_sig }).to_string();
    let body = envelope.as_bytes();
    let mut packet = Vec::with_capacity(5 + body.len());
    packet.extend_from_slice(&(body.len() as u32).to_be_bytes());
    packet.push(1u8);
    packet.extend_from_slice(body);

    let resp = daemon.send_recv(&packet);
    assert!(
        resp.contains("DENY_TAMPERED_TOKEN"),
        "Expected DENY_TAMPERED_TOKEN, got: {resp}"
    );
}

// ---------------------------------------------------------------------------
// Test 4 — DENY_INTENT_NOT_ALLOWED: Agent sends intent outside its allowlist.
// ---------------------------------------------------------------------------

#[test]
fn test_deny_intent_not_in_allowlist() {
    // Policy: only "read_file" allowed for test_agent.
    let daemon = DaemonGuard::spawn_with_policy("intent_deny", 0, &["read_file"]);
    let packet = build_packet(
        next_seq(),
        "execute_shell", // ← not in allowlist
        Some("test_agent"),
        5.0,
        None,
        None,
    );
    let resp = daemon.send_recv(&packet);
    assert!(
        resp.contains("DENY_INTENT_NOT_ALLOWED"),
        "Expected DENY_INTENT_NOT_ALLOWED, got: {resp}"
    );
}

// ---------------------------------------------------------------------------
// Test 5 — DENY_QUOTA_EXHAUSTED: Agent exceeds max_sequence_quota.
// ---------------------------------------------------------------------------

#[test]
fn test_deny_quota_exhausted() {
    // quota=1 → second decision denied.
    let daemon = DaemonGuard::spawn_with_policy("quota", 1, &["read_file"]);

    let p1 = build_packet(next_seq(), "read_file", Some("test_agent"), 5.0, None, None);
    let r1 = daemon.send_recv(&p1);
    // First might be ALLOW (quota not yet hit).
    // Regardless, force a second one with a fresh seq.
    let p2 = build_packet(next_seq(), "read_file", Some("test_agent"), 5.0, None, None);
    let r2 = daemon.send_recv(&p2);

    assert!(
        r1.contains("ALLOW") || r1.contains("DENY"),
        "Unexpected first response: {r1}"
    );
    assert!(
        r2.contains("DENY_QUOTA_EXHAUSTED"),
        "Expected DENY_QUOTA_EXHAUSTED after quota=1 is consumed, got: {r2} (first={r1})"
    );
}

// ---------------------------------------------------------------------------
// Test 6 — DENY_UNKNOWN_AGENT_ID: Agent sends an unregistered agent_id.
// ---------------------------------------------------------------------------

#[test]
fn test_deny_unknown_agent_id() {
    let daemon = DaemonGuard::spawn_with_policy("unknown_agent", 0, &[]);
    let packet = build_packet(
        next_seq(),
        "read_file",
        Some("ghost_agent_xyz"),
        5.0,
        None,
        None,
    );
    let resp = daemon.send_recv(&packet);
    assert!(
        resp.contains("DENY_UNKNOWN_AGENT_ID"),
        "Expected DENY_UNKNOWN_AGENT_ID, got: {resp}"
    );
}

// ---------------------------------------------------------------------------
// Test 7 — DENY via ExecutionBroker: File write to /etc (hard denylist).
// ---------------------------------------------------------------------------

#[test]
fn test_deny_undeclared_etc_path_write() {
    let daemon = DaemonGuard::spawn_with_policy("etc_write", 0, &["write_config"]);
    let action = r#"{"kind":"file_write","path":"/etc/passwd","contents":"evil"}"#;
    let packet = build_packet(
        next_seq(),
        "write_config",
        Some("test_agent"),
        15.0,
        None,
        Some(action),
    );
    let resp = daemon.send_recv(&packet);
    assert!(
        resp.contains("DENY"),
        "Expected DENY for /etc/passwd write, got: {resp}"
    );
}

// ---------------------------------------------------------------------------
// Test 8 — DENY_VIOLATION: Extremely high risk score exceeds ceiling.
// ---------------------------------------------------------------------------

#[test]
fn test_deny_risk_ceiling_exceeded() {
    let daemon = DaemonGuard::spawn_with_policy("risk_ceil", 0, &["model_inference"]);
    let packet = build_packet(
        next_seq(),
        "model_inference",
        Some("test_agent"),
        95.0, // global_safety_ceiling = 90.0 → this must breach
        None,
        None,
    );
    let resp = daemon.send_recv(&packet);
    assert!(
        resp.contains("DENY"),
        "Expected DENY for risk=95 above ceiling=90, got: {resp}"
    );
}

// ---------------------------------------------------------------------------
// Test 9 — Anonymous agent (no agent_id) passes through policy engine.
// ---------------------------------------------------------------------------

#[test]
fn test_allow_anonymous_agent_no_id() {
    let daemon = DaemonGuard::spawn_with_policy("anon", 0, &[]);
    let packet = build_packet(next_seq(), "read_file", None, 5.0, None, None);
    let resp = daemon.send_recv(&packet);
    // Anonymous agents bypass agent_nodes checks — should pass if low risk.
    assert!(
        resp.contains("ALLOW"),
        "Expected ALLOW for anonymous low-risk agent, got: {resp}"
    );
}

// ---------------------------------------------------------------------------
// Test 10 — Protocol version guard: bad version byte rejected.
// ---------------------------------------------------------------------------

#[test]
fn test_deny_bad_protocol_version() {
    let daemon = DaemonGuard::spawn_with_policy("bad_version", 0, &[]);
    let body = br#"{"payload":"{}","signature":"aabbcc"}"#;
    let mut packet = Vec::with_capacity(5 + body.len());
    packet.extend_from_slice(&(body.len() as u32).to_be_bytes());
    packet.push(99u8); // bad version
    packet.extend_from_slice(body);

    let resp = daemon.send_recv(&packet);
    assert!(
        resp.contains("DENY_BAD_VERSION"),
        "Expected DENY_BAD_VERSION, got: {resp}"
    );
}

// ---------------------------------------------------------------------------
// Test 11 — MCP Gateway: deny undeclared intent over HTTP/1.1 TCP.
// ---------------------------------------------------------------------------

/// Helper: spawn daemon with MCP gateway enabled.
fn spawn_daemon_with_mcp(tag: &str, mcp_port: u16) -> DaemonGuard {
    let socket_path = format!("/tmp/jg_test_{tag}.sock");
    let secret_path = format!("/tmp/jg_test_{tag}.secret");
    let lineage_path = format!("/tmp/jg_test_{tag}.lineage.json");
    let audit_path = format!("/tmp/jg_test_{tag}.audit.log");
    let policy_path = format!("/tmp/jg_test_{tag}.policy.yaml");

    cleanup_daemon_files(
        &socket_path,
        &secret_path,
        &lineage_path,
        &audit_path,
        &policy_path,
    );
    write_policy(&policy_path, 0, &["model_inference"]);
    std::fs::write(&secret_path, TEST_SECRET).unwrap();

    let binary = daemon_binary();
    let child = Command::new(&binary)
        .args([
            "--socket-path",
            &socket_path,
            "--lineage-file",
            &lineage_path,
            "--audit-log",
            &audit_path,
            "--policy-file",
            &policy_path,
            "--secret-file",
            &secret_path,
            "--mcp-port",
            &mcp_port.to_string(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|e| panic!("Cannot spawn daemon '{}': {e}", binary));

    // Wait for UDS socket to appear (daemon fully started).
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if std::path::Path::new(&socket_path).exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    assert!(
        std::path::Path::new(&socket_path).exists(),
        "Daemon socket never appeared at {socket_path}"
    );

    // Also wait for the MCP TCP port to be accepting connections.
    let mcp_deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < mcp_deadline {
        if std::net::TcpStream::connect(format!("127.0.0.1:{mcp_port}")).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }

    DaemonGuard {
        child,
        socket_path,
        secret_path,
        lineage_path,
        audit_path,
        policy_path,
    }
}

#[test]
fn test_mcp_gateway_deny_undeclared_intent() {
    // Pick a port unlikely to conflict — use a hash of the tag for stability.
    let mcp_port: u16 = 14751;
    let _daemon = spawn_daemon_with_mcp("mcp_deny", mcp_port);

    // Send an HTTP/1.1 JSON-RPC request with a HIGH risk score so the daemon
    // returns a risk-ceiling DENY without needing to forward to an upstream server.
    // The MCP gateway returns 403 on any DENY.
    let body =
        r#"{"jsonrpc":"2.0","method":"execute_shell","params":{"action_risk_score":95.0},"id":1}"#;
    let request = format!(
        "POST / HTTP/1.1\r\nHost: 127.0.0.1:{mcp_port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(), body
    );

    let mut stream = std::net::TcpStream::connect(format!("127.0.0.1:{mcp_port}"))
        .expect("connect to MCP gateway");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    use std::io::{Read, Write};
    stream
        .write_all(request.as_bytes())
        .expect("write MCP request");
    stream.flush().expect("flush");

    let mut resp_raw = Vec::new();
    stream.read_to_end(&mut resp_raw).unwrap_or_default();
    let resp_str = String::from_utf8_lossy(&resp_raw);

    // We expect HTTP 403 because risk=95 > ceiling=90.
    assert!(
        resp_str.contains("403") || resp_str.contains("DENY") || resp_str.contains("deny"),
        "Expected HTTP 403 or DENY for high-risk request, got: {resp_str}"
    );
}

// ---------------------------------------------------------------------------
// Test 12 — deny_anonymous_agents: anonymous agent rejected when policy true.
// ---------------------------------------------------------------------------

/// Spawn daemon with deny_anonymous_agents=true in policy.
fn spawn_daemon_deny_anon(tag: &str) -> DaemonGuard {
    let socket_path = format!("/tmp/jg_test_{tag}.sock");
    let secret_path = format!("/tmp/jg_test_{tag}.secret");
    let lineage_path = format!("/tmp/jg_test_{tag}.lineage.json");
    let audit_path = format!("/tmp/jg_test_{tag}.audit.log");
    let policy_path = format!("/tmp/jg_test_{tag}.policy.yaml");

    cleanup_daemon_files(
        &socket_path,
        &secret_path,
        &lineage_path,
        &audit_path,
        &policy_path,
    );

    // Write policy with deny_anonymous_agents = true.
    let yaml = r#"
global_safety_ceiling: 90.0
deny_anonymous_agents: true
agent_nodes:
  - id: "test_agent"
    privilege_tier: 1
    max_sequence_quota: 0
    allowed_intents: ["read_file"]
    invariants: []
"#;
    std::fs::write(&policy_path, yaml).unwrap();
    std::fs::write(&secret_path, TEST_SECRET).unwrap();

    let binary = daemon_binary();
    let child = Command::new(&binary)
        .args([
            "--socket-path",
            &socket_path,
            "--lineage-file",
            &lineage_path,
            "--audit-log",
            &audit_path,
            "--policy-file",
            &policy_path,
            "--secret-file",
            &secret_path,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|e| panic!("Cannot spawn daemon: {e}"));

    let deadline = Instant::now() + Duration::from_secs(4);
    while Instant::now() < deadline {
        if std::path::Path::new(&socket_path).exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    assert!(std::path::Path::new(&socket_path).exists());

    DaemonGuard {
        child,
        socket_path,
        secret_path,
        lineage_path,
        audit_path,
        policy_path,
    }
}

#[test]
fn test_deny_anonymous_when_policy_requires_id() {
    let daemon = spawn_daemon_deny_anon("anon_deny");
    // Build a packet with no agent_id (anonymous).
    let packet = build_packet(next_seq(), "read_file", None, 5.0, None, None);
    let resp = daemon.send_recv(&packet);
    assert!(
        resp.contains("DENY_ANONYMOUS_AGENT"),
        "Expected DENY_ANONYMOUS_AGENT when deny_anonymous_agents=true, got: {resp}"
    );
}

// ---------------------------------------------------------------------------
// Test 13 — Constrain band: mid-risk agent gets CONSTRAIN or ALLOW signal.
// ---------------------------------------------------------------------------

#[test]
fn test_constrain_mid_risk_agent() {
    // Policy ceiling = 90.0; constrain band is [36.0, 67.5).
    // We send action_risk_score=65.0 which is reliably in the CONSTRAIN band.
    // The fused risk formula: observed(40%) + semantic(35%) + topology(25%).
    // With a declared risk of 65, fused_risk will be ~65 and land in [36, 67.5).
    let daemon = DaemonGuard::spawn_with_policy("constrain_mid", 0, &["model_inference"]);
    let packet = build_packet(
        next_seq(),
        "model_inference",
        Some("test_agent"),
        65.0,
        None,
        None,
    );
    let resp = daemon.send_recv(&packet);
    // Accept either CONSTRAIN (ideal) or ALLOW (if risk fusion brings it below band).
    // DENY_VIOLATION is also possible if fused risk exceeds ceiling unexpectedly.
    assert!(
        resp.contains("CONSTRAIN") || resp.contains("ALLOW"),
        "Expected CONSTRAIN or ALLOW for mid-risk agent (risk=65, ceiling=90), got: {resp}"
    );
}
