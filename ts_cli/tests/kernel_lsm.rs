// tests/kernel_lsm.rs
//
// Privileged kernel-mediated enforcement tests.
//
// Run on a Linux host with BPF LSM enabled and the LSM object installed:
//   export PATH="$PATH:/usr/sbin"
//   sudo PATH="$PATH" make -C bpf install
//   cargo build -p ts_cli --features enterprise
//   sudo -E env "PATH=$PATH" JINNGUARD_TEST_BINARY=target/debug/ts_cli \
//     cargo test -p ts_cli --features enterprise --test kernel_lsm -- \
//     --ignored --test-threads=1 --nocapture

use std::fs::{self, OpenOptions};
use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};

static PORT_SEQ: AtomicUsize = AtomicUsize::new(48_000);

const TEST_SECRET: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn daemon_binary() -> String {
    std::env::var("JINNGUARD_TEST_BINARY").unwrap_or_else(|_| {
        let manifest = env!("CARGO_MANIFEST_DIR");
        format!("{manifest}/../target/debug/ts_cli")
    })
}

fn write_policy(path: &str, fs_root: &str) {
    let yaml = format!(
        r#"
global_safety_ceiling: 90.0
network_policy:
  default_deny: false
  denied_ips:
    - "127.0.0.1"
agent_nodes:
  - id: "kernel_agent"
    privilege_tier: 1
    max_sequence_quota: 0
    allowed_intents: []
    allowed_executables:
      - "/bin/echo"
      - "/usr/bin/echo"
    denied_write_paths:
      - "{fs_root}"
    denied_unlink_paths:
      - "{fs_root}"
    invariants: []
"#
    );
    fs::write(path, yaml).unwrap_or_else(|err| panic!("write policy {path}: {err}"));
}

fn operation_count() -> usize {
    let count = std::env::var("JINN_KERNEL_LSM_OPS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(1_000);
    assert!(
        count >= 100,
        "JINN_KERNEL_LSM_OPS must be at least the 100-operation smoke minimum"
    );
    count
}

struct DaemonGuard {
    child: Child,
    socket_path: String,
    secret_path: String,
    lineage_path: String,
    audit_path: String,
    policy_path: String,
}

impl DaemonGuard {
    fn spawn(name: &str, fs_root: &str) -> Self {
        Self::spawn_with_env(name, fs_root, &[])
    }

    fn spawn_with_env(name: &str, fs_root: &str, extra_env: &[(&str, &str)]) -> Self {
        let socket_path = format!("/tmp/jg_kernel_lsm_{name}.sock");
        let secret_path = format!("/tmp/jg_kernel_lsm_{name}.secret");
        let lineage_path = format!("/tmp/jg_kernel_lsm_{name}.lineage.json");
        let audit_path = format!("/tmp/jg_kernel_lsm_{name}.audit.log");
        let policy_path = format!("/tmp/jg_kernel_lsm_{name}.policy.yaml");

        let _ = fs::remove_file(&socket_path);
        let _ = fs::remove_file(&secret_path);
        let _ = fs::remove_file(&lineage_path);
        let _ = fs::remove_file(format!("{lineage_path}.db"));
        let _ = fs::remove_file(&audit_path);
        let _ = fs::remove_file(format!("{audit_path}.db"));
        write_policy(&policy_path, fs_root);
        fs::write(&secret_path, TEST_SECRET).unwrap();

        let mcp_port = PORT_SEQ.fetch_add(1, Ordering::Relaxed).to_string();
        let mut command = Command::new(daemon_binary());
        command
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
                &mcp_port,
            ])
            .env("JINNGUARD_ENTERPRISE", "1")
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        for (key, value) in extra_env {
            command.env(key, value);
        }

        let child = command
            .spawn()
            .unwrap_or_else(|err| panic!("spawn enterprise daemon: {err}"));

        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if std::path::Path::new(&socket_path).exists() {
                return Self {
                    child,
                    socket_path,
                    secret_path,
                    lineage_path,
                    audit_path,
                    policy_path,
                };
            }
            thread::sleep(Duration::from_millis(50));
        }

        panic!(
            "enterprise daemon did not create its socket; verify BPF LSM privileges and /usr/lib/jinnguard/jinnguard_lsm.o"
        );
    }
}

impl Drop for DaemonGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_file(&self.socket_path);
        let _ = fs::remove_file(&self.secret_path);
        let _ = fs::remove_file(&self.lineage_path);
        let _ = fs::remove_file(format!("{}.db", self.lineage_path));
        let _ = fs::remove_file(&self.audit_path);
        let _ = fs::remove_file(format!("{}.db", self.audit_path));
        let _ = fs::remove_file(&self.policy_path);
    }
}

#[derive(Clone, Copy)]
enum ExpectedDecision {
    Allow,
    Deny,
}

#[derive(Default)]
struct DecisionStats {
    latencies_us: Vec<u128>,
    success: usize,
    denied: usize,
    fail_open: usize,
    timeout: usize,
    incorrect_decision: usize,
    expected_allow: usize,
    expected_deny: usize,
}

impl DecisionStats {
    fn record<F>(&mut self, expected: ExpectedDecision, mut operation: F)
    where
        F: FnMut() -> io::Result<()>,
    {
        match expected {
            ExpectedDecision::Allow => self.expected_allow += 1,
            ExpectedDecision::Deny => self.expected_deny += 1,
        }

        let start = Instant::now();
        let result = operation();
        let elapsed = start.elapsed();
        self.latencies_us.push(elapsed.as_micros());

        match (expected, result) {
            (ExpectedDecision::Allow, Ok(())) => self.success += 1,
            (ExpectedDecision::Deny, Err(err)) if err.kind() == io::ErrorKind::PermissionDenied => {
                self.denied += 1
            }
            (ExpectedDecision::Deny, Ok(())) => {
                self.success += 1;
                self.fail_open += 1;
            }
            (_, Err(err)) if err.kind() == io::ErrorKind::TimedOut => self.timeout += 1,
            (ExpectedDecision::Allow, Err(err))
                if err.kind() == io::ErrorKind::PermissionDenied =>
            {
                self.denied += 1;
                self.incorrect_decision += 1;
            }
            (_, Err(_)) => self.incorrect_decision += 1,
        }
    }

    fn assert_expected_and_report(&mut self, label: &str) {
        self.latencies_us.sort_unstable();
        let p50 = percentile(&self.latencies_us, 50.0);
        let p95 = percentile(&self.latencies_us, 95.0);
        let p99 = percentile(&self.latencies_us, 99.0);
        let max = self.latencies_us.last().copied().unwrap_or(0);
        println!(
            "[KERNEL_LSM_{label}] operations={} expected_allow={} expected_deny={} success={} deny={} fail_open={} timeout={} incorrect_decision={} P50={}us P95={}us P99={}us MAX={}us",
            self.latencies_us.len(),
            self.expected_allow,
            self.expected_deny,
            self.success,
            self.denied,
            self.fail_open,
            self.timeout,
            self.incorrect_decision,
            p50,
            p95,
            p99,
            max,
        );

        assert_eq!(self.fail_open, 0, "{label}: denied operation succeeded");
        assert_eq!(self.timeout, 0, "{label}: operation timed out");
        assert_eq!(
            self.incorrect_decision, 0,
            "{label}: operation returned an incorrect decision or unexpected error"
        );
        assert_eq!(
            self.success, self.expected_allow,
            "{label}: not all allowed operations succeeded"
        );
        assert_eq!(
            self.denied, self.expected_deny,
            "{label}: not all denied operations returned EPERM"
        );
    }
}

fn percentile(samples: &[u128], pct: f64) -> u128 {
    if samples.is_empty() {
        return 0;
    }
    let rank = ((pct / 100.0) * ((samples.len() - 1) as f64)).round() as usize;
    samples[rank.min(samples.len() - 1)]
}

fn fs_root(name: &str) -> PathBuf {
    let path = PathBuf::from(format!("/tmp/jg_kernel_lsm_{name}_fs"));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).unwrap();
    path
}

fn first_existing(candidates: &[&str]) -> String {
    candidates
        .iter()
        .find(|path| std::path::Path::new(path).exists())
        .unwrap_or_else(|| panic!("none of these paths exist: {candidates:?}"))
        .to_string()
}

fn spawn_accept_loop(listener: TcpListener) -> (Arc<AtomicBool>, thread::JoinHandle<()>) {
    listener.set_nonblocking(true).unwrap();
    let running = Arc::new(AtomicBool::new(true));
    let accept_running = Arc::clone(&running);
    let (ready_tx, ready_rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        let _ = ready_tx.send(());
        while accept_running.load(Ordering::Relaxed) {
            loop {
                match listener.accept() {
                    Ok((_stream, _addr)) => {
                        // Drop accepted sockets immediately; the test only needs
                        // completed handshakes and an empty accept queue.
                    }
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
                    Err(_) => break,
                }
            }
            thread::sleep(Duration::from_micros(100));
        }
    });
    ready_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("accept loop ready");
    (running, handle)
}

fn finish_accept_loop(running: Arc<AtomicBool>, handle: thread::JoinHandle<()>) {
    running.store(false, Ordering::Relaxed);
    let _ = handle.join();
}

fn command_status_success(mut command: Command) -> io::Result<()> {
    let status = command
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::Other,
            format!("command exited with {status}"),
        ))
    }
}

#[test]
#[ignore = "requires root/CAP_BPF, BPF LSM boot param, and installed Jinn Guard LSM objects"]
fn test_kernel_safe_mode_allows_normally_denied_operations() {
    const SAFE_MODE_OPS_PER_SURFACE: usize = 50;

    let denied_root = fs_root("safe_mode_denied");
    let original_cwd = std::env::current_dir().unwrap();
    for idx in 0..SAFE_MODE_OPS_PER_SURFACE {
        fs::write(
            denied_root.join(format!("safe_unlink_{idx}.txt")),
            b"prepared",
        )
        .unwrap();
    }

    let daemon = DaemonGuard::spawn_with_env(
        "safe_mode",
        denied_root.to_str().unwrap(),
        &[("JINNGUARD_SAFE_MODE", "1")],
    );
    assert!(
        std::path::Path::new(&daemon.socket_path).exists(),
        "safe-mode daemon socket was not created"
    );

    let denied_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let denied_tcp_addr = denied_listener.local_addr().unwrap();
    let (tcp_running, tcp_thread) = spawn_accept_loop(denied_listener);

    let denied_udp_server = UdpSocket::bind("127.0.0.1:0").unwrap();
    let denied_udp_addr = denied_udp_server.local_addr().unwrap();
    let udp_client = UdpSocket::bind("127.0.0.2:0").unwrap();

    let denied_exec = first_existing(&["/bin/true", "/usr/bin/true"]);
    let mut stats = DecisionStats::default();

    for idx in 0..SAFE_MODE_OPS_PER_SURFACE {
        let denied_exec = denied_exec.clone();
        stats.record(ExpectedDecision::Allow, || {
            command_status_success(Command::new(&denied_exec))
        });

        stats.record(ExpectedDecision::Allow, || {
            TcpStream::connect_timeout(&denied_tcp_addr, Duration::from_millis(250)).map(|_| ())
        });

        stats.record(ExpectedDecision::Allow, || {
            udp_client
                .send_to(b"jinn-guard-safe-mode", denied_udp_addr)
                .map(|_| ())
        });

        std::env::set_current_dir(&denied_root).unwrap();
        stats.record(ExpectedDecision::Allow, || {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(format!("safe_create_{idx}.txt"))
                .map(|_| ())
        });

        std::env::set_current_dir(&denied_root).unwrap();
        stats.record(ExpectedDecision::Allow, || {
            fs::remove_file(format!("safe_unlink_{idx}.txt"))
        });
    }

    std::env::set_current_dir(original_cwd).unwrap();
    finish_accept_loop(tcp_running, tcp_thread);

    stats.assert_expected_and_report("SAFE_MODE_AUDIT_ONLY");
    assert_eq!(stats.success, SAFE_MODE_OPS_PER_SURFACE * 5);
    assert_eq!(stats.denied, 0, "safe mode returned deny decisions");
    assert_eq!(stats.timeout, 0, "safe mode operations timed out");

    drop(daemon);
    let _ = fs::remove_dir_all(denied_root);
}

#[test]
#[ignore = "requires root/CAP_BPF, BPF LSM boot param, and /usr/lib/jinnguard/jinnguard_lsm.o"]
fn test_kernel_tcp_blocking_percentiles() {
    let root = fs_root("tcp");
    let daemon = DaemonGuard::spawn("tcp", root.to_str().unwrap());

    let denied_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let denied_addr = denied_listener.local_addr().unwrap();
    let (denied_running, denied_thread) = spawn_accept_loop(denied_listener);

    let allowed_listener = TcpListener::bind("127.0.0.2:0").unwrap();
    let allowed_addr = allowed_listener.local_addr().unwrap();
    let (allowed_running, allowed_thread) = spawn_accept_loop(allowed_listener);

    let mut stats = DecisionStats::default();
    for idx in 0..operation_count() {
        let (expected, addr): (ExpectedDecision, SocketAddr) = if idx % 2 == 0 {
            (ExpectedDecision::Allow, allowed_addr)
        } else {
            (ExpectedDecision::Deny, denied_addr)
        };
        stats.record(expected, || {
            TcpStream::connect_timeout(&addr, Duration::from_millis(250)).map(|_| ())
        });
    }
    finish_accept_loop(denied_running, denied_thread);
    finish_accept_loop(allowed_running, allowed_thread);
    stats.assert_expected_and_report("TCP_CONNECT");
    drop(daemon);
    let _ = fs::remove_dir_all(root);
}

#[test]
#[ignore = "requires root/CAP_BPF, BPF LSM boot param, and /usr/lib/jinnguard/jinnguard_lsm.o"]
fn test_kernel_udp_blocking_percentiles() {
    let root = fs_root("udp");
    let daemon = DaemonGuard::spawn("udp", root.to_str().unwrap());

    let denied_server = UdpSocket::bind("127.0.0.1:0").unwrap();
    let denied_addr = denied_server.local_addr().unwrap();
    let allowed_server = UdpSocket::bind("127.0.0.2:0").unwrap();
    let allowed_addr = allowed_server.local_addr().unwrap();
    let client = UdpSocket::bind("127.0.0.2:0").unwrap();

    let mut stats = DecisionStats::default();
    for idx in 0..operation_count() {
        let (expected, addr): (ExpectedDecision, SocketAddr) = if idx % 2 == 0 {
            (ExpectedDecision::Allow, allowed_addr)
        } else {
            (ExpectedDecision::Deny, denied_addr)
        };
        stats.record(expected, || {
            client.send_to(b"jinn-guard-lsm", addr).map(|_| ())
        });
    }
    stats.assert_expected_and_report("UDP_SENDTO");
    drop(daemon);
    let _ = fs::remove_dir_all(root);
}

#[test]
#[ignore = "requires root/CAP_BPF, BPF LSM boot param, and /usr/lib/jinnguard/jinnguard_lsm.o"]
fn test_kernel_execve_blocking_percentiles() {
    let root = fs_root("execve");
    let daemon = DaemonGuard::spawn("execve", root.to_str().unwrap());
    let allowed = first_existing(&["/bin/echo", "/usr/bin/echo"]);
    let denied = first_existing(&["/bin/true", "/usr/bin/true"]);

    let mut stats = DecisionStats::default();
    for idx in 0..operation_count() {
        if idx % 2 == 0 {
            let allowed = allowed.clone();
            stats.record(ExpectedDecision::Allow, || {
                let mut command = Command::new(&allowed);
                command.arg("allowed");
                command_status_success(command)
            });
        } else {
            let denied = denied.clone();
            stats.record(ExpectedDecision::Deny, || {
                command_status_success(Command::new(&denied))
            });
        }
    }
    stats.assert_expected_and_report("EXECVE");
    drop(daemon);
    let _ = fs::remove_dir_all(root);
}

#[test]
#[ignore = "requires root/CAP_BPF, BPF LSM boot param, and /usr/lib/jinnguard/jinnguard_lsm.o"]
fn test_kernel_filesystem_create_blocking_percentiles() {
    let denied_root = fs_root("filesystem_create_denied");
    let allowed_root = fs_root("filesystem_create_allowed");
    let daemon = DaemonGuard::spawn("filesystem_create", denied_root.to_str().unwrap());
    let original_cwd = std::env::current_dir().unwrap();

    let mut stats = DecisionStats::default();
    for idx in 0..operation_count() {
        if idx % 2 == 0 {
            std::env::set_current_dir(&allowed_root).unwrap();
            stats.record(ExpectedDecision::Allow, || {
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(format!("allow_create_{idx}.txt"))
                    .map(|_| ())
            });
        } else {
            std::env::set_current_dir(&denied_root).unwrap();
            stats.record(ExpectedDecision::Deny, || {
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(format!("deny_create_{idx}.txt"))
                    .map(|_| ())
            });
        }
    }

    std::env::set_current_dir(original_cwd).unwrap();
    stats.assert_expected_and_report("FILESYSTEM_CREATE");
    drop(daemon);
    let _ = fs::remove_dir_all(denied_root);
    let _ = fs::remove_dir_all(allowed_root);
}

#[test]
#[ignore = "requires root/CAP_BPF, BPF LSM boot param, and /usr/lib/jinnguard/jinnguard_lsm.o"]
fn test_kernel_filesystem_unlink_blocking_percentiles() {
    let denied_root = fs_root("filesystem_unlink_denied");
    let allowed_root = fs_root("filesystem_unlink_allowed");
    for idx in 0..operation_count() {
        if idx % 2 == 0 {
            fs::write(
                allowed_root.join(format!("allow_unlink_{idx}.txt")),
                b"prepared",
            )
            .unwrap();
        } else {
            fs::write(
                denied_root.join(format!("deny_unlink_{idx}.txt")),
                b"prepared",
            )
            .unwrap();
        }
    }

    let daemon = DaemonGuard::spawn("filesystem_unlink", denied_root.to_str().unwrap());
    let original_cwd = std::env::current_dir().unwrap();

    let mut stats = DecisionStats::default();
    for idx in 0..operation_count() {
        if idx % 2 == 0 {
            std::env::set_current_dir(&allowed_root).unwrap();
            stats.record(ExpectedDecision::Allow, || {
                fs::remove_file(format!("allow_unlink_{idx}.txt"))
            });
        } else {
            std::env::set_current_dir(&denied_root).unwrap();
            stats.record(ExpectedDecision::Deny, || {
                fs::remove_file(format!("deny_unlink_{idx}.txt"))
            });
        }
    }

    std::env::set_current_dir(original_cwd).unwrap();
    stats.assert_expected_and_report("FILESYSTEM_UNLINK");
    drop(daemon);
    let _ = fs::remove_dir_all(denied_root);
    let _ = fs::remove_dir_all(allowed_root);
}
