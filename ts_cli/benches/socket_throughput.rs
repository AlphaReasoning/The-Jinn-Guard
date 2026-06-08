// benches/socket_throughput.rs
//
// End-to-end UDS socket saturation benchmark for Jinn Guard.
//
// Unlike the internal Z3 benchmarks in throughput.rs, this harness:
//   1. Spawns the full jinnguard daemon binary as a child process
//   2. Drives concurrent client connections via tokio tasks
//   3. Reports P50/P95 wall-clock latencies and derived RPS
//
// Usage:
//   cargo bench --bench socket_throughput
//
// Prerequisites:
//   - A compiled ts_cli binary at target/debug/ts_cli (or target/release/ts_cli)
//   - A valid HMAC secret loaded into the kernel keyring OR present at
//     /etc/jinnguard/secret, OR the binary must fall back gracefully.
//     For CI, set JINNGUARD_TEST_SECRET env var and the harness will write
//     a temp secret file.
//
// Environment variables:
//   JINNGUARD_BENCH_BINARY  Path to the daemon binary (default: target/debug/ts_cli)
//   JINNGUARD_BENCH_SOCKET  Socket path override (default: /tmp/jg_bench_e2e.sock)
//   JINNGUARD_TEST_SECRET   Hex secret for HMAC (default: uses dev fallback key)

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const BENCH_SOCKET: &str = "/tmp/jg_bench_e2e.sock";
const BENCH_SECRET_FILE: &str = "/tmp/jg_bench_secret";
const BENCH_LINEAGE: &str = "/tmp/jg_bench_lineage.json";
const BENCH_AUDIT: &str = "/tmp/jg_bench_audit.log";
const BENCH_POLICY: &str = "/tmp/jg_bench_policy.yaml";
const DEV_SECRET: &str = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

fn secret_key() -> Vec<u8> {
    std::env::var("JINNGUARD_TEST_SECRET")
        .unwrap_or_else(|_| DEV_SECRET.to_string())
        .into_bytes()
}

fn daemon_binary() -> String {
    std::env::var("JINNGUARD_BENCH_BINARY").unwrap_or_else(|_| "target/debug/ts_cli".to_string())
}

fn bench_socket_path() -> String {
    std::env::var("JINNGUARD_BENCH_SOCKET").unwrap_or_else(|_| BENCH_SOCKET.to_string())
}

/// Write a minimal policy.yaml for the bench daemon.
fn write_bench_policy() {
    let yaml = r#"
global_safety_ceiling: 90.0
agent_nodes:
  - id: "bench_agent"
    privilege_tier: 1
    max_sequence_quota: 0
    allowed_intents: []
    invariants: []
"#;
    std::fs::write(BENCH_POLICY, yaml).expect("write bench policy");
}

/// Write a temp secret file so the daemon can start without the kernel keyring.
fn write_bench_secret() {
    let key = std::env::var("JINNGUARD_TEST_SECRET").unwrap_or_else(|_| DEV_SECRET.to_string());
    std::fs::write(BENCH_SECRET_FILE, &key).expect("write bench secret");
    // mode 0400 owner check in daemon — skip for bench (it runs as same user).
}

/// HMAC-sign a payload string.
fn sign_payload(payload: &str, key: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(key).unwrap();
    mac.update(payload.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Build a minimal signed framed packet.
fn build_packet(seq: u64, agent_id: &str, key: &[u8]) -> Vec<u8> {
    let payload = format!(
        r#"{{"sequence_counter":{seq},"intent_name":"read_file","agent_id":"{agent_id}","action_risk_score":10.0}}"#
    );
    let sig = sign_payload(&payload, key);
    let envelope = format!(r#"{{"payload":{payload:?},"signature":"{sig}"}}"#);

    let body = envelope.as_bytes();
    let mut packet = Vec::with_capacity(5 + body.len());
    packet.extend_from_slice(&(body.len() as u32).to_be_bytes());
    packet.push(1u8); // protocol version
    packet.extend_from_slice(body);
    packet
}

/// Spawn the daemon as a child process and wait until the socket is ready.
struct DaemonGuard {
    child: Child,
    socket_path: String,
}

impl DaemonGuard {
    fn spawn() -> Self {
        let socket_path = bench_socket_path();
        let _ = std::fs::remove_file(&socket_path);

        write_bench_policy();
        write_bench_secret();

        let binary = daemon_binary();
        let child = Command::new(&binary)
            .args([
                "--socket-path",
                &socket_path,
                "--lineage-file",
                BENCH_LINEAGE,
                "--audit-log",
                BENCH_AUDIT,
                "--policy-file",
                BENCH_POLICY,
            ])
            .env("JINNGUARD_SECRET_FILE", BENCH_SECRET_FILE)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap_or_else(|e| {
                panic!(
                    "Failed to spawn daemon binary '{}': {e}\n\
                Run 'cargo build' first, or set JINNGUARD_BENCH_BINARY.",
                    binary
                )
            });

        // Wait for socket to appear (up to 5 seconds).
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if UnixStream::connect(&socket_path).is_ok() {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }

        assert!(
            std::path::Path::new(&socket_path).exists(),
            "Daemon socket never appeared at {socket_path} — is the binary working?"
        );

        DaemonGuard { child, socket_path }
    }
}

impl Drop for DaemonGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = std::fs::remove_file(&self.socket_path);
        let _ = std::fs::remove_file(BENCH_SECRET_FILE);
        let _ = std::fs::remove_file(BENCH_LINEAGE);
        let _ = std::fs::remove_file(BENCH_AUDIT);
        let _ = std::fs::remove_file(BENCH_POLICY);
    }
}

/// Read a framed response from a blocking UnixStream.
fn read_response(stream: &mut UnixStream) -> Vec<u8> {
    let mut header = [0u8; 5];
    stream
        .read_exact(&mut header)
        .expect("read response header");
    let len = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize;
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).expect("read response body");
    body
}

// ---------------------------------------------------------------------------
// Benchmark 1: Serial framed roundtrip — one connection per request.
//              Models new-connection overhead + full governance pipeline.
// ---------------------------------------------------------------------------

fn bench_serial_roundtrip(c: &mut Criterion) {
    let daemon = Arc::new(DaemonGuard::spawn());
    let key = secret_key();
    let socket = daemon.socket_path.clone();

    let mut group = c.benchmark_group("e2e_serial_roundtrip");
    group.throughput(Throughput::Elements(1));
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(200);

    group.bench_function("new_connection_per_request", |b| {
        let mut seq: u64 = 1_000_000;
        b.iter(|| {
            seq += 1;
            let packet = build_packet(seq, "bench_agent", &key);
            let mut stream = UnixStream::connect(&socket).expect("connect");
            stream.write_all(&packet).expect("write");
            stream.flush().expect("flush");
            let resp = read_response(&mut stream);
            assert!(!resp.is_empty());
            resp
        });
    });

    group.finish();
    drop(daemon);
}

// ---------------------------------------------------------------------------
// Benchmark 2: Persistent connection — single socket, many proposals.
//              This is the minimum-latency ceiling for the governance pipeline.
// ---------------------------------------------------------------------------

fn bench_persistent_connection(c: &mut Criterion) {
    let daemon = Arc::new(DaemonGuard::spawn());
    let key = secret_key();
    let socket = daemon.socket_path.clone();

    let mut group = c.benchmark_group("e2e_persistent_connection");
    group.throughput(Throughput::Elements(1));
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(500);

    group.bench_function("reuse_connection", |b| {
        let mut stream = UnixStream::connect(&socket).expect("connect persistent");
        let mut seq: u64 = 2_000_000;
        b.iter(|| {
            seq += 1;
            let packet = build_packet(seq, "bench_agent", &key);
            stream.write_all(&packet).expect("write");
            stream.flush().expect("flush");
            let resp = read_response(&mut stream);
            assert!(!resp.is_empty());
            resp
        });
    });

    group.finish();
    drop(daemon);
}

// ---------------------------------------------------------------------------
// Benchmark 3: P50/P95 latency distribution + derived RPS.
//
// This benchmark is not a standard criterion microbench — it drives a fixed
// number of sequential requests and directly computes percentile latencies.
// Results are printed to stdout; criterion runs it once for the wall-clock
// numbers.
// ---------------------------------------------------------------------------

fn bench_latency_distribution(c: &mut Criterion) {
    let daemon = Arc::new(DaemonGuard::spawn());
    let key = secret_key();
    let socket = daemon.socket_path.clone();

    let mut group = c.benchmark_group("e2e_latency_distribution");

    group.bench_function("p50_p95_report", |b| {
        b.iter_custom(|iters| {
            let mut latencies: Vec<Duration> = Vec::with_capacity(iters as usize);
            let mut seq: u64 = 3_000_000;

            for _ in 0..iters {
                seq += 1;
                let packet = build_packet(seq, "bench_agent", &key);
                let t0 = Instant::now();
                let mut stream = UnixStream::connect(&socket).expect("connect");
                stream.write_all(&packet).expect("write");
                stream.flush().expect("flush");
                let _ = read_response(&mut stream);
                latencies.push(t0.elapsed());
            }

            // Compute and report percentiles.
            latencies.sort_unstable();
            let p50 = latencies[latencies.len() / 2];
            let p95 = latencies[(latencies.len() as f64 * 0.95) as usize];
            let total: Duration = latencies.iter().sum();
            let rps = latencies.len() as f64 / total.as_secs_f64();

            println!(
                "\n  [E2E Latency] n={} | P50={:.2}ms | P95={:.2}ms | RPS={:.0}",
                latencies.len(),
                p50.as_secs_f64() * 1000.0,
                p95.as_secs_f64() * 1000.0,
                rps,
            );

            total
        });
    });

    group.finish();
    drop(daemon);
}

criterion_group!(
    socket_benches,
    bench_serial_roundtrip,
    bench_persistent_connection,
    bench_latency_distribution,
);
criterion_main!(socket_benches);
