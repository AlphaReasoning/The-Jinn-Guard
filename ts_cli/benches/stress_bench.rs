// benches/stress_bench.rs
//
// Hardcore stress test and benchmark suite for Jinn Guard.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

type HmacSha256 = Hmac<Sha256>;

const BENCH_SECRET_FILE: &str = "/tmp/jg_stress_secret";
const BENCH_LINEAGE: &str = "/tmp/jg_stress_lineage.json";
const BENCH_AUDIT: &str = "/tmp/jg_stress_audit.log";
const BENCH_POLICY: &str = "/tmp/jg_stress_policy.yaml";
const DEV_SECRET: &str = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

static SEQ: AtomicU64 = AtomicU64::new(10_000_000);

fn next_seq() -> u64 {
    SEQ.fetch_add(1, Ordering::Relaxed)
}

fn daemon_binary() -> String {
    std::env::var("JINNGUARD_BENCH_BINARY").unwrap_or_else(|_| {
        let manifest = env!("CARGO_MANIFEST_DIR");
        format!("{}/../target/release/ts_cli", manifest)
    })
}

fn write_stress_policy() {
    let mut yaml = String::from("global_safety_ceiling: 90.0\nagent_nodes:\n  - id: \"bench_agent\"\n    privilege_tier: 1\n    max_sequence_quota: 0\n    allowed_intents: [\"read_file\"]\n    invariants: []\n");
    for i in 0..501 {
        yaml.push_str(&format!("  - id: \"swarm_agent_{}\"\n    privilege_tier: 1\n    max_sequence_quota: 0\n    allowed_intents: [\"read_file\"]\n    invariants: []\n", i));
    }
    std::fs::write(BENCH_POLICY, yaml).expect("write bench policy");
}

fn write_stress_secret() {
    std::fs::write(BENCH_SECRET_FILE, DEV_SECRET).expect("write bench secret");
}

fn sign_payload(payload: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(DEV_SECRET.as_bytes()).unwrap();
    mac.update(payload.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn build_packet(seq: u64, agent_id: &str, risk: f64, intent: &str) -> Vec<u8> {
    let payload = format!(
        r#"{{"sequence_counter":{seq},"intent_name":"{intent}","agent_id":"{agent_id}","action_risk_score":{risk}}}"#
    );
    let sig = sign_payload(&payload);
    let envelope = format!(r#"{{"payload":{payload:?},"signature":"{sig}"}}"#);
    let body = envelope.as_bytes();
    let mut packet = Vec::with_capacity(5 + body.len());
    packet.extend_from_slice(&(body.len() as u32).to_be_bytes());
    packet.push(1u8);
    packet.extend_from_slice(body);
    packet
}

struct DaemonGuard {
    child: Child,
    socket_path: String,
}

impl DaemonGuard {
    fn spawn(tag: &str) -> Self {
        let socket_path = format!("/tmp/jg_stress_{}.sock", tag);
        let _ = std::fs::remove_file(&socket_path);

        write_stress_policy();
        write_stress_secret();

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
                "--secret-file",
                BENCH_SECRET_FILE,
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap_or_else(|e| panic!("Failed to spawn daemon: {e}"));

        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if UnixStream::connect(&socket_path).is_ok() {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }

        DaemonGuard { child, socket_path }
    }
}

impl Drop for DaemonGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.socket_path);
        let _ = std::fs::remove_file(BENCH_SECRET_FILE);
        let _ = std::fs::remove_file(BENCH_LINEAGE);
        let _ = std::fs::remove_file(format!("{}.db", BENCH_LINEAGE));
        let _ = std::fs::remove_file(BENCH_AUDIT);
        let _ = std::fs::remove_file(format!("{}.db", BENCH_AUDIT));
        let _ = std::fs::remove_file(BENCH_POLICY);
    }
}

fn read_response(stream: &mut UnixStream) -> String {
    let mut header = [0u8; 5];
    stream.read_exact(&mut header).expect("read header");
    let len = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize;
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).expect("read body");
    String::from_utf8_lossy(&body).to_string()
}

// ── GROUP 1: latency_percentiles ─────────────────────────

fn group_latency_percentiles() {
    let daemon = DaemonGuard::spawn("latency");
    let n = 10_000;
    let mut latencies = Vec::with_capacity(n);
    let t_start = Instant::now();

    for _ in 0..n {
        let seq = next_seq();
        let packet = build_packet(seq, "bench_agent", 5.0, "read_file");
        let t0 = Instant::now();
        let mut stream = UnixStream::connect(&daemon.socket_path).expect("connect");
        stream.write_all(&packet).expect("write");
        let _ = read_response(&mut stream);
        latencies.push(t0.elapsed());
    }

    let total_dur = t_start.elapsed();
    latencies.sort_unstable();

    let p50 = latencies[n / 2];
    let p75 = latencies[n * 3 / 4];
    let p90 = latencies[n * 9 / 10];
    let p95 = latencies[n * 19 / 20];
    let p99 = latencies[n * 99 / 100];
    let p999 = latencies[n * 999 / 1000];
    let max = latencies[n - 1];
    let rps = n as f64 / total_dur.as_secs_f64();

    println!("\n[LATENCY] n={}", n);
    println!("    P50:   {}µs", p50.as_micros());
    println!("    P75:   {}µs", p75.as_micros());
    println!("    P90:   {}µs", p90.as_micros());
    println!("    P95:   {}µs", p95.as_micros());
    println!("    P99:   {}µs", p99.as_micros());
    println!("    P99.9: {}µs", p999.as_micros());
    println!("    MAX:   {}µs", max.as_micros());
    println!("    RPS:   {:.0}", rps);
}

// ── GROUP 2: concurrent_swarm ────────────────────────────

fn run_swarm(daemon_path: &str, n_agents: usize, m_requests: usize) {
    let mut threads = Vec::with_capacity(n_agents);
    let t_start = Instant::now();

    for i in 0..n_agents {
        let path = daemon_path.to_string();
        let agent_id = format!("swarm_agent_{}", i);
        threads.push(thread::spawn(move || {
            let mut stream = UnixStream::connect(&path).expect("connect");
            let mut local_latencies = Vec::with_capacity(m_requests);
            for _ in 0..m_requests {
                let seq = next_seq();
                let packet = build_packet(seq, &agent_id, 5.0, "read_file");
                let t0 = Instant::now();
                stream.write_all(&packet).expect("write");
                let resp = read_response(&mut stream);
                assert!(resp.contains("ALLOW"));
                local_latencies.push(t0.elapsed());
            }
            local_latencies
        }));
    }

    let mut all_latencies = Vec::with_capacity(n_agents * m_requests);
    for t in threads {
        all_latencies.extend(t.join().unwrap());
    }

    let total_dur = t_start.elapsed();
    let total_reqs = n_agents * m_requests;
    let rps = total_reqs as f64 / total_dur.as_secs_f64();

    all_latencies.sort_unstable();
    let p50 = all_latencies[total_reqs / 2];
    let p95 = all_latencies[total_reqs * 19 / 20];

    println!(
        "\n[SWARM] agents={}  requests_each={}",
        n_agents, m_requests
    );
    println!("    Total RPS:  {:.0}", rps);
    println!("    P50:        {}µs", p50.as_micros());
    println!("    P95:        {}µs", p95.as_micros());
    println!("    Errors:     0");
}

fn group_concurrent_swarm() {
    let daemon = DaemonGuard::spawn("swarm");

    run_swarm(&daemon.socket_path, 10, 500);
    run_swarm(&daemon.socket_path, 50, 200);
    run_swarm(&daemon.socket_path, 100, 100);
    run_swarm(&daemon.socket_path, 500, 20);
}

// ── GROUP 3: mixed_workload ──────────────────────────────

fn group_mixed_workload() {
    let daemon = DaemonGuard::spawn("mixed");
    let n = 5_000;
    let mut allow_latencies = Vec::new();
    let mut deny_latencies = Vec::new();
    let t_start = Instant::now();

    for i in 0..n {
        let seq = next_seq();
        let (packet, expected) = if i < (n * 7 / 10) {
            (build_packet(seq, "bench_agent", 5.0, "read_file"), "ALLOW")
        } else if i < (n * 9 / 10) {
            (
                build_packet(seq, "bench_agent", 5.0, "unauthorized_intent"),
                "DENY",
            )
        } else {
            (build_packet(seq, "bench_agent", 95.0, "read_file"), "DENY")
        };

        let t0 = Instant::now();
        let mut stream = UnixStream::connect(&daemon.socket_path).expect("connect");
        stream.write_all(&packet).expect("write");
        let resp = read_response(&mut stream);
        let dur = t0.elapsed();

        assert!(resp.contains(expected));
        if expected == "ALLOW" {
            allow_latencies.push(dur);
        } else {
            deny_latencies.push(dur);
        }
    }

    let total_dur = t_start.elapsed();
    println!("\n[MIXED] n={}", n);
    println!("    ALLOW count: {}", allow_latencies.len());
    println!("    DENY count:  {}", deny_latencies.len());
    println!(
        "    Total RPS:    {:.0}",
        n as f64 / total_dur.as_secs_f64()
    );
}

// ── GROUP 4: throughput_saturation ───────────────────────

fn group_throughput_saturation() {
    let daemon = DaemonGuard::spawn("saturation");

    println!("\n[SATURATION]");
    for &threads_count in &[2, 4, 8, 16, 32, 64] {
        let mut handles = Vec::with_capacity(threads_count);
        let t_start = Instant::now();

        for _ in 0..threads_count {
            let path = daemon.socket_path.clone();
            handles.push(thread::spawn(move || {
                let mut local_latencies = Vec::with_capacity(200);
                for _ in 0..200 {
                    let packet = build_packet(next_seq(), "bench_agent", 5.0, "read_file");
                    let t0 = Instant::now();
                    let mut stream = UnixStream::connect(&path).expect("connect");
                    stream.write_all(&packet).expect("write");
                    let _ = read_response(&mut stream);
                    local_latencies.push(t0.elapsed());
                }
                local_latencies
            }));
        }

        let mut all_latencies = Vec::new();
        for h in handles {
            all_latencies.extend(h.join().unwrap());
        }

        let total_dur = t_start.elapsed();
        let total_count = all_latencies.len();
        let rps = total_count as f64 / total_dur.as_secs_f64();
        all_latencies.sort_unstable();
        let p99 = all_latencies[total_count * 99 / 100];

        if p99.as_millis() > 10 {
            println!("    threads={}:   SATURATED (P99 > 10ms)", threads_count);
            break;
        } else {
            println!(
                "    threads={}:   {:.0}  RPS   P99={}ms",
                threads_count,
                rps,
                p99.as_millis()
            );
        }
    }
}

// ── GROUP 5: mcp_gateway_stress ──────────────────────────

fn group_mcp_gateway_stress() {
    let port_str = std::env::var("MCP_BENCH_PORT").unwrap_or_else(|_| "4750".to_string());
    let port: u16 = port_str.parse().unwrap();
    let addr = format!("127.0.0.1:{}", port);

    if std::net::TcpStream::connect(&addr).is_err() {
        println!("\n[MCP GATEWAY] skipped — set MCP_BENCH_PORT to enable");
        return;
    }

    let n = 1_000;
    let mut latencies = Vec::with_capacity(n);
    let t_start = Instant::now();
    let body = r#"{"jsonrpc":"2.0","method":"read_file","params":{},"id":1}"#;

    for _ in 0..n {
        let request = format!(
            "POST / HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            addr, body.len(), body
        );
        let t0 = Instant::now();
        let mut stream = std::net::TcpStream::connect(&addr).expect("connect mcp");
        stream.write_all(request.as_bytes()).expect("write");
        let mut buffer = [0u8; 4096];
        let _ = stream.read(&mut buffer).expect("read");
        latencies.push(t0.elapsed());
    }

    let total_dur = t_start.elapsed();
    latencies.sort_unstable();
    let p50 = latencies[n / 2];
    let p95 = latencies[n * 19 / 20];
    let rps = n as f64 / total_dur.as_secs_f64();

    println!("\n[MCP GATEWAY] n={}", n);
    println!("    Total RPS: {:.0}", rps);
    println!("    P50:       {}µs", p50.as_micros());
    println!("    P95:       {}µs", p95.as_micros());
}

fn main() {
    group_latency_percentiles();
    group_concurrent_swarm();
    group_mixed_workload();
    group_throughput_saturation();
    group_mcp_gateway_stress();
}
