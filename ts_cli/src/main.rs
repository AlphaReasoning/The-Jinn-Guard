#![cfg(target_os = "linux")]

pub mod ebpf_monitor;

use std::fs;
use std::io::{Read, Write};
use std::path::Path;
use std::os::unix::net::UnixListener;
use std::os::unix::io::AsRawFd;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use serde_json::Value;
use ts_checker::PolicyEngine;
use z3::{Config, Context};
use signal_hook::{consts::SIGHUP, iterator::Signals};
use hmac::{Hmac, Mac, KeyInit};
use sha2::Sha256;
use constant_time_eq::constant_time_eq;

type HmacSha256 = Hmac<Sha256>;

struct PolicyConfig {
    upper_safety_boundary: f64,
}

#[derive(Clone)]
pub struct ProcessTokenState {
    pub expected_signature: String,
    pub maximum_allowed_risk: f64,
    pub last_sequence: u64,
}

fn load_policy() -> PolicyConfig {
    if let Ok(content) = fs::read_to_string("jinnguard_policy.json") {
        if let Ok(json_data) = serde_json::from_str::<Value>(&content) {
            return PolicyConfig {
                upper_safety_boundary: json_data["upper_safety_boundary"].as_f64().unwrap_or(75.0),
            };
        }
    }
    PolicyConfig { upper_safety_boundary: 75.0 }
}

fn get_runtime_secret() -> anyhow::Result<Vec<u8>> {
    std::env::var("JINN_GUARD_SECRET")
        .map(|s| s.into_bytes())
        .map_err(|_| anyhow::anyhow!("CRITICAL: JINN_GUARD_SECRET register is uninitialized."))
}

fn verify_token_signature(payload_str: &str, hex_sig: &str) -> bool {
    let secret = match get_runtime_secret() {
        Ok(k) => k,
        Err(_) => return false,
    };
    let mut mac = HmacSha256::new_from_slice(&secret).unwrap();
    mac.update(payload_str.as_bytes());
    let result = mac.finalize();
    
    if let Ok(target_bytes) = hex::decode(hex_sig) {
        return constant_time_eq(result.into_bytes().as_slice(), target_bytes.as_slice());
    }
    false
}

fn get_socket_peer_pid(stream: &std::os::unix::net::UnixStream) -> u32 {
    let fd = stream.as_raw_fd();
    unsafe {
        let mut ucred = libc::ucred { pid: 0, uid: 0, gid: 0 };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        
        let res = libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut ucred as *mut _ as *mut libc::c_void,
            &mut len,
        );
        
        if res == 0 {
            ucred.pid as u32
        } else {
            0
        }
    }
}

fn handle_client_connection(
    mut stream: std::os::unix::net::UnixStream, 
    current_policy: PolicyConfig,
    registry: Arc<Mutex<HashMap<u32, ProcessTokenState>>>
) {
    let authenticated_pid = get_socket_peer_pid(&stream);
    if authenticated_pid == 0 {
        println!("    🔒 [SECURITY BREACH] Failed to resolve kernel peer credentials.");
        return;
    }

    // FIXED: Active Memory Leak Pruning. Scans the registry and drops dead entries.
    {
        let mut reg = registry.lock().unwrap();
        reg.retain(|pid, _| {
            let proc_path = format!("/proc/{}", pid);
            Path::new(&proc_path).exists()
        });
    }

    let mut buffer = [0; 4096];
    match stream.read(&mut buffer) {
        Ok(size) => {
            let raw_wire_packet = String::from_utf8_lossy(&buffer[..size]);
            
            if let Ok(envelope) = serde_json::from_str::<Value>(&raw_wire_packet) {
                let payload_raw = envelope["payload"].as_str().unwrap_or("");
                let signature = envelope["signature"].as_str().unwrap_or("");

                if !verify_token_signature(payload_raw, signature) {
                    println!("    🔒 [SECURITY BREACH] Crypto token payload signature mismatch! Dropping pipe.");
                    let _ = stream.write_all(b"SIGNAL: DENY_TAMPERED_TOKEN\n");
                    return;
                }

                if let Ok(json_data) = serde_json::from_str::<Value>(payload_raw) {
                    let live_privilege = json_data["session_privilege_bit"].as_f64().unwrap_or(0.0);
                    let live_risk = json_data["action_risk_score"].as_f64().unwrap_or(20.0);
                    let current_sequence = json_data["sequence_counter"].as_u64().unwrap_or(0);
                    let ceiling = current_policy.upper_safety_boundary;

                    println!("\n📥 [RECEIVE] Auditing Kernel-Verified PID [{}] -> Risk: {}, Privilege: {} [Sequence={}]", 
                             authenticated_pid, live_risk, live_privilege, current_sequence);

                    {
                        let mut reg = registry.lock().unwrap();
                        let state = reg.entry(authenticated_pid).or_insert(ProcessTokenState {
                            expected_signature: signature.to_string(),
                            maximum_allowed_risk: live_risk,
                            last_sequence: 0,
                        });

                        if current_sequence <= state.last_sequence && state.last_sequence != 0 {
                            println!("    🔒 [REPLAY ATTACK INTERCEPTED] Outdated sequence parameter trace.");
                            let _ = stream.write_all(b"SIGNAL: DENY_REPLAY_ATTACK\n");
                            return;
                        }
                        state.last_sequence = current_sequence;

                        if live_risk > state.maximum_allowed_risk {
                            println!("    🛑 [BEHAVIORAL DRIFT] PID [{}] breached initial risk contract anchor.", authenticated_pid);
                            let _ = stream.write_all(b"SIGNAL: DENY_BEHAVIORAL_DRIFT\n");
                            return;
                        }
                    }

                    if live_risk > ceiling {
                        println!("    🛑 [INGRESS BLOCK] Token vector violates operational ceiling.");
                        let _ = stream.write_all(b"SIGNAL: DENY_VIOLATION\n");
                        return;
                    }

                    let config = Config::new();
                    let ctx = Context::new(&config);
                    let mut checker = PolicyEngine::new(&ctx);
                    let _ = checker.register_bounded_geometry();

                    match checker.execute_totality_audit(live_privilege, live_risk, ceiling) {
                        Ok(_) => {
                            println!("    ✅ [PROOF VALIDATED]: Emitting structural ALLOW signal for PID [{}].", authenticated_pid);
                            let _ = stream.write_all(b"SIGNAL: ALLOW\n");
                        }
                        Err(e) => {
                            println!("    🛑 [PROOF FAILURE]: Boundary exposure caught: {}", e);
                            let _ = stream.write_all(b"SIGNAL: DENY_VIOLATION\n");
                        }
                    }
                }
            } else {
                let _ = stream.write_all(b"ERROR: Invalid packet wire structure.\n");
            }
        }
        Err(err) => println!("Connection track execution drop error: {}", err),
    }
}

fn main() -> anyhow::Result<()> {
    if let Err(e) = get_runtime_secret() {
        eprintln!("{}", e);
        std::process::exit(1);
    }

    let socket_path = "/tmp/jinnguard.sock";
    if Path::new(socket_path).exists() {
        fs::remove_file(socket_path)?;
    }

    let process_registry = Arc::new(Mutex::new(HashMap::<u32, ProcessTokenState>::new()));

    println!("--- Step 1: Spawning Asynchronous Policy Watcher Thread ---");
    let active_policy = Arc::new(Mutex::new(load_policy()));
    
    let policy_clone = Arc::clone(&active_policy);
    let mut signals = Signals::new(&[SIGHUP])?;
    std::thread::spawn(move || {
        for sig in signals.forever() {
            if sig == SIGHUP {
                println!("\n🔄 [HOT RELOAD] Refreshing configuration matrix parameters...");
                if let Ok(mut policy) = policy_clone.lock() {
                    *policy = load_policy();
                    println!("   [SUCCESS] Live Invariant Boundary Reset To: {}", policy.upper_safety_boundary);
                }
            }
        }
    });

    println!("--- Step 2: Binding Asynchronous Multi-Worker Connection Listener Pool ---");
    let listener = UnixListener::bind(socket_path)?;
    println!("🚀 JINN GUARD HARDENED SO_PEERCRED INTERFACE ACTIVE: {}...", socket_path);
    println!("----------------------------------------------------------------------");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let policy_snapshot = {
                    let lock = active_policy.lock().unwrap();
                    PolicyConfig { upper_safety_boundary: lock.upper_safety_boundary }
                };
                let registry_clone = Arc::clone(&process_registry);
                
                std::thread::spawn(move || {
                    handle_client_connection(stream, policy_snapshot, registry_clone);
                });
            }
            Err(err) => println!("Worker interface thread drop error: {}", err),
        }
    }

    Ok(())
}
