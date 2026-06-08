use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use std::collections::HashMap;
use ts_checker::PolicyEngine;
use z3::{Config, Context};

// ---------------------------------------------------------------------------
// Benchmark 1: Z3 verify_state_transition (risk ceiling check hot path)
// ---------------------------------------------------------------------------

fn bench_z3_state_transition(c: &mut Criterion) {
    let config = Config::new();
    let ctx = Context::new(&config);
    let engine = PolicyEngine::new(&ctx);
    let _ = engine.register_bounded_geometry();

    let mut group = c.benchmark_group("z3_state_transition");
    for risk in [10i64, 30, 50, 70, 90] {
        group.bench_with_input(BenchmarkId::from_parameter(risk), &risk, |b, &risk| {
            b.iter(|| engine.verify_state_transition(black_box(0), black_box(risk), black_box(95)))
        });
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmark 2: Z3 verify_policy_invariants (G2 enforcement path)
// ---------------------------------------------------------------------------

fn bench_z3_policy_invariants(c: &mut Criterion) {
    let config = Config::new();
    let ctx = Context::new(&config);
    let engine = PolicyEngine::new(&ctx);

    let invariants_2 = vec![
        "spending_ceiling_usd <= 150.00".to_string(),
        "privilege_escalation_depth < 3".to_string(),
    ];
    let invariants_5 = vec![
        "spending_ceiling_usd <= 150.00".to_string(),
        "privilege_escalation_depth < 3".to_string(),
        "fused_risk <= 75.0".to_string(),
        "trust_score >= 25.0".to_string(),
        "decisions_seen < 100.0".to_string(),
    ];

    let context_vars: HashMap<String, f64> = [
        ("spending_ceiling_usd".to_string(), 75.0_f64),
        ("privilege_escalation_depth".to_string(), 1.0_f64),
        ("fused_risk".to_string(), 40.0_f64),
        ("trust_score".to_string(), 60.0_f64),
        ("decisions_seen".to_string(), 5.0_f64),
    ]
    .into_iter()
    .collect();

    let mut group = c.benchmark_group("z3_policy_invariants");
    group.bench_function("2_constraints", |b| {
        b.iter(|| {
            engine.verify_policy_invariants(black_box(&invariants_2), black_box(&context_vars))
        })
    });
    group.bench_function("5_constraints", |b| {
        b.iter(|| {
            engine.verify_policy_invariants(black_box(&invariants_5), black_box(&context_vars))
        })
    });
    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmark 3: Totality audit (per-connection hot path)
// ---------------------------------------------------------------------------

fn bench_totality_audit(c: &mut Criterion) {
    let config = Config::new();
    let ctx = Context::new(&config);
    let engine = PolicyEngine::new(&ctx);
    let _ = engine.register_bounded_geometry();

    let mut group = c.benchmark_group("totality_audit");
    for (assessed, ceiling) in [(35.0f64, 75.0f64), (74.9, 75.0), (90.0, 95.0)] {
        let label = format!("risk_{:.0}_ceil_{:.0}", assessed, ceiling);
        group.bench_with_input(
            BenchmarkId::from_parameter(&label),
            &(assessed, ceiling),
            |b, &(risk, ceil)| {
                b.iter(|| engine.execute_totality_audit(black_box(risk), black_box(ceil)))
            },
        );
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmark 4: UDS socket saturation — end-to-end framed write+read latency
//
// Spawns a minimal echo server on a UNIX domain socket in a background thread,
// then measures how fast the bench thread can send a framed 5-byte header +
// JSON payload and receive the echoed response.
//
// This directly models the daemon's per-connection IPC path and gives us the
// raw transport ceiling that the full policy pipeline must stay under.
// ---------------------------------------------------------------------------

fn bench_uds_socket_saturation(c: &mut Criterion) {
    use std::io::{Read, Write};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::thread;

    let socket_path = "/tmp/jinnguard_bench_saturation.sock";
    let _ = std::fs::remove_file(socket_path);

    // Minimal framed echo server.
    let listener = UnixListener::bind(socket_path).expect("bind bench socket");
    thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = match stream {
                Ok(s) => s,
                Err(_) => break,
            };
            thread::spawn(move || {
                let mut header = [0u8; 5];
                loop {
                    if stream.read_exact(&mut header).is_err() {
                        break;
                    }
                    let len =
                        u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize;
                    if len > 65_536 {
                        break;
                    }
                    let mut payload = vec![0u8; len];
                    if stream.read_exact(&mut payload).is_err() {
                        break;
                    }
                    // Echo the exact framed message back.
                    let _ = stream.write_all(&header);
                    let _ = stream.write_all(&payload);
                    let _ = stream.flush();
                }
            });
        }
    });

    // Give the server a moment to bind.
    std::thread::sleep(std::time::Duration::from_millis(50));

    // Payload: a realistic minimal ClientProposal JSON.
    let payload = br#"{"sequence_counter":1,"intent_name":"model_inference","agent_id":"fabric_swarm_production_01","action_risk_score":30.0}"#;
    let payload_len = payload.len() as u32;
    let mut header = [0u8; 5];
    header[..4].copy_from_slice(&payload_len.to_be_bytes());
    header[4] = 1; // protocol version

    let mut group = c.benchmark_group("uds_socket_saturation");
    group.throughput(Throughput::Elements(1));
    group.bench_function("framed_roundtrip", |b| {
        // Each iteration opens a fresh connection (models real agent connect pattern).
        b.iter(|| {
            let mut stream =
                UnixStream::connect(socket_path).expect("bench: connect to echo server");
            stream.write_all(&header).unwrap();
            stream.write_all(black_box(payload)).unwrap();
            stream.flush().unwrap();

            let mut resp_header = [0u8; 5];
            stream.read_exact(&mut resp_header).unwrap();
            let resp_len = u32::from_be_bytes([
                resp_header[0],
                resp_header[1],
                resp_header[2],
                resp_header[3],
            ]) as usize;
            let mut resp = vec![0u8; resp_len];
            stream.read_exact(&mut resp).unwrap();
            resp
        })
    });

    // Persistent connection benchmark — models a long-lived agent session.
    group.bench_function("framed_roundtrip_persistent_conn", |b| {
        let mut stream = UnixStream::connect(socket_path).expect("bench: connect persistent");
        b.iter(|| {
            stream.write_all(&header).unwrap();
            stream.write_all(black_box(payload)).unwrap();
            stream.flush().unwrap();

            let mut resp_header = [0u8; 5];
            stream.read_exact(&mut resp_header).unwrap();
            let resp_len = u32::from_be_bytes([
                resp_header[0],
                resp_header[1],
                resp_header[2],
                resp_header[3],
            ]) as usize;
            let mut resp = vec![0u8; resp_len];
            stream.read_exact(&mut resp).unwrap();
            resp
        })
    });

    group.finish();

    let _ = std::fs::remove_file(socket_path);
}

criterion_group!(
    benches,
    bench_z3_state_transition,
    bench_z3_policy_invariants,
    bench_totality_audit,
    bench_uds_socket_saturation,
);
criterion_main!(benches);
