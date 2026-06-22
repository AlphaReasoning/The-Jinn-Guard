// tests/kernel_lsm.rs
//
// Privileged kernel-mediated enforcement tests.
//
// Run on a Linux host with BPF LSM enabled and the LSM object installed:
//   export PATH="$PATH:/usr/sbin"
//   sudo PATH="$PATH" make -C bpf install
//   cargo build -p ts_cli --features enterprise
//   sudo -E env "PATH=$PATH" JINNGUARD_TEST_BINARY="$PWD/target/debug/ts_cli" \
//     cargo test -p ts_cli --features enterprise --test kernel_lsm -- \
//     --ignored --test-threads=1 --nocapture
//
// NOTE: `JINNGUARD_TEST_BINARY` must be ABSOLUTE. `cargo test -p ts_cli` runs the
// test binary with its cwd set to the package dir (ts_cli/), not the workspace
// root, so a relative `target/debug/ts_cli` resolves to a nonexistent
// `ts_cli/target/debug/ts_cli`. Omitting the var entirely also works (the
// daemon_binary() fallback uses an absolute CARGO_MANIFEST_DIR-relative path).

use std::fs::{self, OpenOptions};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::unix::net::{UnixListener, UnixStream};
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

/// A dedicated cgroup-v2 leaf used to confine kernel enforcement to this test
/// process and its children. The daemon is told to govern only this cgroup
/// (`JINNGUARD_GOVERN_CGROUP`), so arming real allow/deny here can never touch
/// the rest of the host — the operator's desktop is structurally out of scope.
struct CgroupScope {
    path: PathBuf,
}

impl CgroupScope {
    fn create(name: &str) -> Self {
        let base = PathBuf::from("/sys/fs/cgroup");
        assert!(
            base.join("cgroup.controllers").exists(),
            "cgroup v2 must be mounted at /sys/fs/cgroup to run the armed kernel tests"
        );
        let path = base.join(format!("jinnguard_test_{name}"));
        let _ = fs::remove_dir(&path);
        fs::create_dir(&path)
            .unwrap_or_else(|err| panic!("create test cgroup {}: {err}", path.display()));
        Self { path }
    }

    fn as_str(&self) -> &str {
        self.path.to_str().expect("cgroup path is valid UTF-8")
    }

    /// Move this (whole) process into the scoped cgroup. Children spawned
    /// afterwards inherit it, so their execve/connect/file ops are governed.
    fn enter(&self) {
        let pid = std::process::id().to_string();
        fs::write(self.path.join("cgroup.procs"), &pid)
            .unwrap_or_else(|err| panic!("move test process into {}: {err}", self.path.display()));
    }

    /// Return to the root cgroup. Idempotent; also lets the leaf be removed and
    /// ensures any teardown work is no longer governed.
    fn leave() {
        let pid = std::process::id().to_string();
        let _ = fs::write("/sys/fs/cgroup/cgroup.procs", pid);
    }
}

impl Drop for CgroupScope {
    fn drop(&mut self) {
        Self::leave();
        // The kernel removes the cgroup only once it is empty; retry briefly.
        for _ in 0..50 {
            if fs::remove_dir(&self.path).is_ok() {
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
    }
}

struct DaemonGuard {
    child: Child,
    socket_path: String,
    secret_path: String,
    lineage_path: String,
    audit_path: String,
    policy_path: String,
    cgroup: CgroupScope,
}

impl DaemonGuard {
    fn spawn(name: &str, fs_root: &str) -> Self {
        Self::spawn_with_env(name, fs_root, &[])
    }

    fn spawn_with_env(name: &str, fs_root: &str, extra_env: &[(&str, &str)]) -> Self {
        Self::spawn_full(name, fs_root, extra_env, None)
    }

    /// Like `spawn_with_env`, but writes a caller-supplied policy YAML verbatim.
    /// Used by the default-deny egress test, which needs `network_policy` knobs
    /// (`default_deny`, `allowed_ips`) the default `write_policy` helper does
    /// not emit.
    fn spawn_with_policy(
        name: &str,
        fs_root: &str,
        policy_yaml: &str,
        extra_env: &[(&str, &str)],
    ) -> Self {
        Self::spawn_full(name, fs_root, extra_env, Some(policy_yaml))
    }

    fn spawn_full(
        name: &str,
        fs_root: &str,
        extra_env: &[(&str, &str)],
        policy_override: Option<&str>,
    ) -> Self {
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
        match policy_override {
            Some(yaml) => fs::write(&policy_path, yaml)
                .unwrap_or_else(|err| panic!("write policy {policy_path}: {err}")),
            None => write_policy(&policy_path, fs_root),
        }
        fs::write(&secret_path, TEST_SECRET).unwrap();

        // Create the scoped cgroup BEFORE the daemon starts so the daemon can
        // resolve its id and confine enforcement to it at attach time.
        let cgroup = CgroupScope::create(name);

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
            .env("JINNGUARD_GOVERN_CGROUP", cgroup.as_str())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        for (key, value) in extra_env {
            command.env(key, value);
        }

        // The daemon itself is spawned while we are still in the root cgroup, so
        // the daemon is never governed by its own hooks.
        let child = command
            .spawn()
            .unwrap_or_else(|err| panic!("spawn enterprise daemon: {err}"));

        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if std::path::Path::new(&socket_path).exists() {
                // Hooks are attached and scoped; now move ourselves (and thus our
                // future probe children) into the governed cgroup.
                cgroup.enter();
                return Self {
                    child,
                    socket_path,
                    secret_path,
                    lineage_path,
                    audit_path,
                    policy_path,
                    cgroup,
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
        // Step out of the governed cgroup first so all teardown below (and the
        // test harness afterwards) runs ungoverned, even though enforcement is
        // still attached until the daemon dies. The `cgroup` field's own Drop
        // then removes the now-empty leaf.
        CgroupScope::leave();
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

/// AF_UNIX analogue of `spawn_accept_loop` for the deputy-denylist test's
/// allowed (non-denylisted) socket. Accepted streams are dropped immediately;
/// the test only needs completed connects.
fn spawn_unix_accept_loop(listener: UnixListener) -> (Arc<AtomicBool>, thread::JoinHandle<()>) {
    listener.set_nonblocking(true).unwrap();
    let running = Arc::new(AtomicBool::new(true));
    let accept_running = Arc::clone(&running);
    let (ready_tx, ready_rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        let _ = ready_tx.send(());
        while accept_running.load(Ordering::Relaxed) {
            loop {
                match listener.accept() {
                    Ok(_) => {}
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
                    Err(_) => break,
                }
            }
            thread::sleep(Duration::from_micros(100));
        }
    });
    ready_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("unix accept loop ready");
    (running, handle)
}

/// Discover a non-loopback IPv4 address assigned to this host. The default-deny
/// egress test needs it to exercise the *allowlist* path: loopback (127.0.0.0/8)
/// is exempt from default-deny in-kernel, so it can never prove an allowlisted
/// non-loopback destination is permitted. The discovery socket is only
/// `connect()`ed (which just selects a source address via the routing table) —
/// no packets are sent — so this needs a configured default route, not network
/// reachability.
fn primary_non_loopback_ipv4() -> Ipv4Addr {
    let probe = UdpSocket::bind("0.0.0.0:0").expect("bind discovery socket");
    probe
        .connect("198.51.100.1:9")
        .expect("select source address on discovery socket");
    match probe.local_addr().expect("discovery local_addr").ip() {
        IpAddr::V4(ip) if !ip.is_loopback() => ip,
        other => panic!(
            "default-deny egress test requires a non-loopback IPv4 on this host; found {other}"
        ),
    }
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

/// JG #49 — governance must be un-sheddable. A task in a *descendant* cgroup of
/// the governed scope is still enforced (cgroup-subtree matching), not just a
/// task in the exact governed cgroup. Under the previous exact-id check, a
/// governed agent could shed enforcement by creating a child cgroup and moving
/// into it (its cgroup id no longer matched); subtree matching closes that.
#[test]
#[ignore = "requires root/CAP_BPF, BPF LSM boot param, and /usr/lib/jinnguard/jinnguard_lsm.o"]
fn test_kernel_governance_subtree_is_unsheddable() {
    let root = fs_root("subtree");
    let daemon = DaemonGuard::spawn("subtree", root.to_str().unwrap());
    let denied = first_existing(&["/bin/true", "/usr/bin/true"]);

    // Baseline: spawn() left us directly in the governed cgroup, where a
    // non-allowlisted exec must be denied (default-deny exec in governed scope).
    let in_scope = command_status_success(Command::new(&denied));
    assert!(
        matches!(&in_scope, Err(e) if e.kind() == io::ErrorKind::PermissionDenied),
        "baseline: exec in the governed cgroup must be denied, got {in_scope:?}"
    );

    // Create a descendant cgroup and migrate this process into it. Its cgroup id
    // differs from the governed scope, so exact-id matching would treat it as
    // out-of-scope and ALLOW the exec; subtree matching must still DENY it.
    let nested = daemon.cgroup.path.join("nested");
    fs::create_dir(&nested)
        .unwrap_or_else(|e| panic!("create nested cgroup {}: {e}", nested.display()));
    fs::write(nested.join("cgroup.procs"), std::process::id().to_string())
        .unwrap_or_else(|e| panic!("migrate into nested cgroup {}: {e}", nested.display()));

    let in_descendant = command_status_success(Command::new(&denied));

    // Step back to the root cgroup BEFORE asserting so teardown (and the rest of
    // the harness) runs ungoverned even if the assertion fails.
    CgroupScope::leave();
    let _ = fs::remove_dir(&nested);

    assert!(
        matches!(&in_descendant, Err(e) if e.kind() == io::ErrorKind::PermissionDenied),
        "JG #49: a task in a descendant of the governed cgroup must remain governed \
         (subtree match), but the exec was not denied: {in_descendant:?}"
    );

    drop(daemon);
    let _ = fs::remove_dir_all(root);
}

/// JG #53 — a governed task may not wield escalation capabilities inside a user
/// namespace it creates. The child first unshares a new user namespace (allowed:
/// the check is in the init ns), then unshares a mount namespace, which requires
/// CAP_SYS_ADMIN evaluated against the new *nested* userns. The capable hook
/// denies that for governed scope, so the second unshare fails with EPERM —
/// neutering the rootless-userns nesting an agent would use to escape the host
/// LSM scope. Run in a forked, single-threaded child because unshare(NEWUSER)
/// is rejected from a multi-threaded process.
#[test]
#[ignore = "requires root/CAP_BPF, BPF LSM boot param, and /usr/lib/jinnguard/jinnguard_lsm.o"]
fn test_kernel_governed_nested_userns_caps_denied() {
    let root = fs_root("userns");
    let daemon = DaemonGuard::spawn("userns", root.to_str().unwrap());

    // spawn() left us in the governed cgroup; the forked child inherits it.
    let code = fork_nested_userns_mount();

    CgroupScope::leave();

    assert_eq!(
        code,
        libc::EPERM,
        "JG #53: governed unshare(CLONE_NEWNS) inside a fresh user namespace must \
         be denied EPERM ({}); got exit code {code} (0=succeeded/escaped, \
         >=200=could not create the userns at all)",
        libc::EPERM
    );

    drop(daemon);
    let _ = fs::remove_dir_all(root);
}

/// Fork a single-threaded child that creates a user namespace and then tries to
/// create a mount namespace inside it; returns the errno of the mount-namespace
/// unshare (0 = unexpectedly succeeded; 200+e = the userns itself could not be
/// created, an environment problem rather than a governance result).
fn fork_nested_userns_mount() -> i32 {
    // SAFETY: the child performs only async-signal-safe syscalls before _exit.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed: {}", io::Error::last_os_error());
    if pid == 0 {
        let r1 = unsafe { libc::unshare(libc::CLONE_NEWUSER) };
        if r1 != 0 {
            let e = io::Error::last_os_error().raw_os_error().unwrap_or(31);
            unsafe { libc::_exit(200 + (e & 0x1f)) };
        }
        let r2 = unsafe { libc::unshare(libc::CLONE_NEWNS) };
        let code = if r2 == 0 {
            0
        } else {
            io::Error::last_os_error().raw_os_error().unwrap_or(255)
        };
        unsafe { libc::_exit(code) };
    }
    let mut status: libc::c_int = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        -1
    }
}

/// JG #50 — a governed task may not create new mounts. mount(2) is denied at the
/// `sb_mount` LSM hook for tasks in the governed cgroup subtree, blocking the
/// filesystem half of nesting a container/sandbox root outside the host LSM
/// scope (the in-kernel complement to #53's capability denial). The target lives
/// OUTSIDE the policy fs_root and a tmpfs needs no block device or allowlisted
/// source, so the EPERM is attributable to the mount hook, not the path
/// allowlist.
#[test]
#[ignore = "requires root/CAP_BPF, BPF LSM boot param, and /usr/lib/jinnguard/jinnguard_lsm.o"]
fn test_kernel_governed_mount_denied() {
    let root = fs_root("mount");
    let daemon = DaemonGuard::spawn("mount", root.to_str().unwrap());

    let target = PathBuf::from("/tmp/jg_mnt_target_mount");
    let _ = fs::remove_dir_all(&target);
    fs::create_dir_all(&target).unwrap();
    let c_target = std::ffi::CString::new(target.to_str().unwrap()).unwrap();

    // spawn() left us in the governed cgroup.
    let rc = unsafe {
        libc::mount(
            c"none".as_ptr(),
            c_target.as_ptr(),
            c"tmpfs".as_ptr(),
            0,
            std::ptr::null(),
        )
    };
    let errno = io::Error::last_os_error().raw_os_error().unwrap_or(0);

    // Undo an unexpected success before asserting so we never leave a stray
    // tmpfs mounted in /tmp.
    if rc == 0 {
        unsafe { libc::umount(c_target.as_ptr()) };
    }

    // Leave the governed cgroup BEFORE asserting so teardown runs ungoverned
    // even if an assertion fails.
    CgroupScope::leave();
    let _ = fs::remove_dir_all(&target);

    assert_eq!(
        rc, -1,
        "JG #50: governed mount(2) must be denied, but it succeeded (rc=0)"
    );
    assert_eq!(
        errno,
        libc::EPERM,
        "JG #50: governed mount(2) must be denied EPERM ({}); got errno {errno}",
        libc::EPERM
    );

    drop(daemon);
    let _ = fs::remove_dir_all(root);
}

/// JG #51 — a governed task may not open /dev/kvm, neutering KVM-accelerated
/// VM/microVM launch (the strongest host-LSM escape: a guest kernel runs outside
/// our hooks). The `file_open` hook matches the device by its fixed identity
/// (MISC_MAJOR 10, KVM_MINOR 232), so we test it WITHOUT depending on real KVM
/// being present on the runner: mknod a char node with rdev (10,232) in /tmp and
/// open it. The LSM file_open hook fires before the device driver's open, so the
/// EPERM is attributable to the hook whether or not /dev/kvm is registered. The
/// node lives OUTSIDE the policy fs_root so no path-allowlist rule is involved.
#[test]
#[ignore = "requires root/CAP_BPF, BPF LSM boot param, and /usr/lib/jinnguard/jinnguard_lsm.o"]
fn test_kernel_governed_vm_launch_denied() {
    let root = fs_root("vmlaunch");
    let daemon = DaemonGuard::spawn("vmlaunch", root.to_str().unwrap());

    // A char device node with the fixed /dev/kvm identity (major 10, minor 232).
    let node = "/tmp/jg_kvm_node_vmlaunch";
    let _ = fs::remove_file(node);
    let c_node = std::ffi::CString::new(node).unwrap();
    let kvm_dev = libc::makedev(10, 232);
    // mknod runs in the governed cgroup (init userns), where CAP_MKNOD is allowed
    // and the node is outside fs_root, so creating it is not itself denied.
    let mk = unsafe { libc::mknod(c_node.as_ptr(), libc::S_IFCHR | 0o600, kvm_dev) };
    assert_eq!(
        mk,
        0,
        "could not mknod the kvm test node: {}",
        io::Error::last_os_error()
    );

    let fd = unsafe { libc::open(c_node.as_ptr(), libc::O_RDWR) };
    let errno = io::Error::last_os_error().raw_os_error().unwrap_or(0);

    // Close an unexpected success before asserting (would only happen if the hook
    // failed to deny AND a real KVM device answered the open).
    if fd >= 0 {
        unsafe { libc::close(fd) };
    }

    // Leave the governed cgroup BEFORE asserting so teardown runs ungoverned.
    CgroupScope::leave();
    let _ = fs::remove_file(node);

    assert_eq!(
        fd, -1,
        "JG #51: governed open(/dev/kvm-identity) must be denied, but it succeeded"
    );
    // Our file_open hook denies with EPERM, and on a stock host that is exactly
    // what surfaces (verified on kernels 6.17 / 5.14). Accept EACCES too: the
    // open traverses the whole LSM stack and the platform device layer, and on
    // some hosts (e.g. one with a real /dev/kvm fronted by an additional access
    // check) a permission-class refusal arrives as EACCES before/around our
    // hook. Both unambiguously mean the governed agent could NOT open the KVM
    // device — the security property under test. ENOENT/ENODEV/0 would not.
    assert!(
        errno == libc::EPERM || errno == libc::EACCES,
        "JG #51: governed /dev/kvm open must be denied with a permission error \
         (EPERM {} or EACCES {}); got errno {errno}",
        libc::EPERM,
        libc::EACCES
    );

    drop(daemon);
    let _ = fs::remove_dir_all(root);
}

/// JG #52 — denied-directory enforcement keys on the directory's filesystem
/// identity `(s_dev, i_ino)`, not on the configured path string. We create a
/// file inside the denied directory but *reach it through a symlink* whose path
/// does not textually match any policy entry. Naive path-string matching would
/// see an unconfigured path and ALLOW the write; identity matching resolves the
/// real parent inode (the denied dir) and DENIES it. This is the mount-remap
/// robustness from THREAT_MODEL §7 item 4 made testable without a mount syscall
/// (which governed scope now denies anyway, #50): a symlink relocates the *name*
/// while preserving the target inode's `(dev, ino)`.
#[test]
#[ignore = "requires root/CAP_BPF, BPF LSM boot param, and /usr/lib/jinnguard/jinnguard_lsm.o"]
fn test_kernel_inode_identity_denied_via_symlink() {
    let denied_root = fs_root("inode_identity");
    let daemon = DaemonGuard::spawn("inode_identity", denied_root.to_str().unwrap());

    // A symlink OUTSIDE the denied dir, pointing at it. Its path matches no
    // policy entry; only the target inode identity does.
    let link = PathBuf::from("/tmp/jg_inode_identity_link");
    let _ = fs::remove_file(&link);
    std::os::unix::fs::symlink(&denied_root, &link)
        .unwrap_or_else(|e| panic!("create identity symlink {}: {e}", link.display()));

    // spawn() left us in the governed cgroup. Create a regular file via the
    // symlinked path; the real parent dir is the denied root.
    let probe = link.join("identity_probe.txt");
    let result = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
        .map(|_| ());

    // Leave the governed cgroup BEFORE asserting so teardown runs ungoverned.
    CgroupScope::leave();
    let _ = fs::remove_file(&probe);
    let _ = fs::remove_file(&link);

    assert!(
        matches!(&result, Err(e) if e.kind() == io::ErrorKind::PermissionDenied),
        "JG #52: a write into the denied directory reached via a non-matching \
         symlink path must be denied by (dev, ino) identity, got {result:?}"
    );

    drop(daemon);
    let _ = fs::remove_dir_all(denied_root);
}

/// JG #60 — a denied *file* path is matched precisely by its parent directory's
/// `(s_dev, i_ino)` identity plus basename, not by basename anywhere in scope.
/// Policy denies exactly `<guarded>/secret.conf`. We assert three things in
/// governed scope: the exact file is denied; a different name in the same dir is
/// allowed (not a directory-wide deny); and — the narrowing that matters — the
/// same basename in a *different* directory is allowed. Basename-only matching
/// (the pre-#60 behavior) would have denied that last case.
#[test]
#[ignore = "requires root/CAP_BPF, BPF LSM boot param, and /usr/lib/jinnguard/jinnguard_lsm.o"]
fn test_kernel_per_file_denial_precise() {
    // Two real directories that exist before the daemon resolves policy, so the
    // denied file's parent `(dev, ino)` is pinned at load.
    let guarded = PathBuf::from("/tmp/jg_perfile_guarded");
    let other = PathBuf::from("/tmp/jg_perfile_other");
    for d in [&guarded, &other] {
        let _ = fs::remove_dir_all(d);
        fs::create_dir_all(d).unwrap_or_else(|e| panic!("create {}: {e}", d.display()));
    }
    let denied_file = guarded.join("secret.conf");

    let policy = format!(
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
    denied_write_paths:
      - "{denied}"
    denied_unlink_paths:
      - "{denied}"
    invariants: []
"#,
        denied = denied_file.display()
    );

    let dummy_root = fs_root("perfile");
    let daemon =
        DaemonGuard::spawn_with_policy("perfile", dummy_root.to_str().unwrap(), &policy, &[]);

    // spawn() left us in the governed cgroup.
    let create = |p: PathBuf| {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(p)
            .map(|_| ())
    };
    let denied_exact = create(guarded.join("secret.conf"));
    let same_dir_other_name = create(guarded.join("allowed.conf"));
    let other_dir_same_name = create(other.join("secret.conf"));

    // Leave the governed cgroup BEFORE asserting so teardown runs ungoverned.
    CgroupScope::leave();
    let _ = fs::remove_dir_all(&guarded);
    let _ = fs::remove_dir_all(&other);

    assert!(
        matches!(&denied_exact, Err(e) if e.kind() == io::ErrorKind::PermissionDenied),
        "JG #60: the exact denied file <guarded>/secret.conf must be denied, got {denied_exact:?}"
    );
    assert!(
        same_dir_other_name.is_ok(),
        "JG #60: a different filename in the guarded dir must be allowed \
         (per-file, not directory-wide), got {same_dir_other_name:?}"
    );
    assert!(
        other_dir_same_name.is_ok(),
        "JG #60: the same basename in a DIFFERENT directory must be allowed \
         (precise (dev,ino,name), not basename-anywhere), got {other_dir_same_name:?}"
    );

    drop(daemon);
    let _ = fs::remove_dir_all(dummy_root);
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

/// #54 — default-deny IPv4 egress. With `network_policy.default_deny: true`, a
/// governed connect to a non-loopback IPv4 is denied unless the destination is
/// in `allowed_ips`; loopback (127.0.0.0/8) stays exempt for anti-lockout.
/// Three surfaces per iteration:
///   * ALLOW — connect to an allowlisted non-loopback host IP (exercises the
///     allowlist hit; loopback alone could not, since it bypasses the lookup).
///   * ALLOW — connect to 127.0.0.2 (loopback exemption / anti-lockout).
///   * DENY  — connect to 198.51.100.9 (RFC 5737 TEST-NET-2: not allowlisted,
///     not loopback, with no listener). The LSM verdict precedes the TCP layer,
///     so EPERM returns immediately; were enforcement off, the connect would
///     instead hit a non-routable sink and time out, failing the test.
#[test]
#[ignore = "requires root/CAP_BPF, BPF LSM boot param, and /usr/lib/jinnguard/jinnguard_lsm.o"]
fn test_kernel_default_deny_egress_percentiles() {
    let root = fs_root("default_deny_egress");
    let host_ip = primary_non_loopback_ipv4();

    let policy = format!(
        r#"
global_safety_ceiling: 90.0
network_policy:
  default_deny: true
  allowed_ips:
    - "{host_ip}"
agent_nodes:
  - id: "kernel_agent"
    privilege_tier: 1
    max_sequence_quota: 0
    allowed_intents: []
    allowed_executables:
      - "/bin/echo"
      - "/usr/bin/echo"
    denied_write_paths:
      - "{root}"
    denied_unlink_paths:
      - "{root}"
    invariants: []
"#,
        host_ip = host_ip,
        root = root.to_str().unwrap(),
    );

    let daemon =
        DaemonGuard::spawn_with_policy("default_deny_egress", root.to_str().unwrap(), &policy, &[]);

    // Allowlisted, non-loopback listener (the host's own IP; the connection is
    // routed internally but the LSM sees the non-loopback destination address).
    let allowed_listener = TcpListener::bind((host_ip, 0)).unwrap();
    let allowed_addr = allowed_listener.local_addr().unwrap();
    let (allowed_running, allowed_thread) = spawn_accept_loop(allowed_listener);

    // Loopback listener — exempt from default-deny regardless of the allowlist.
    let loopback_listener = TcpListener::bind("127.0.0.2:0").unwrap();
    let loopback_addr = loopback_listener.local_addr().unwrap();
    let (loopback_running, loopback_thread) = spawn_accept_loop(loopback_listener);

    // Non-allowlisted, non-loopback sink; no listener (LSM denies first).
    let denied_addr: SocketAddr = "198.51.100.9:9".parse().unwrap();

    let mut stats = DecisionStats::default();
    for _ in 0..operation_count() {
        stats.record(ExpectedDecision::Allow, || {
            TcpStream::connect_timeout(&allowed_addr, Duration::from_millis(250)).map(|_| ())
        });
        stats.record(ExpectedDecision::Allow, || {
            TcpStream::connect_timeout(&loopback_addr, Duration::from_millis(250)).map(|_| ())
        });
        stats.record(ExpectedDecision::Deny, || {
            TcpStream::connect_timeout(&denied_addr, Duration::from_millis(250)).map(|_| ())
        });
    }

    finish_accept_loop(allowed_running, allowed_thread);
    finish_accept_loop(loopback_running, loopback_thread);
    stats.assert_expected_and_report("DEFAULT_DENY_EGRESS");
    drop(daemon);
    let _ = fs::remove_dir_all(root);
}

/// #55 — AF_UNIX deputy-socket denylist. A governed connect to a built-in
/// orchestrator control socket (`/run/docker.sock`) is denied, closing the
/// confused-deputy path (agent -> dockerd -> ungoverned root); a connect to an
/// ordinary, non-denylisted unix socket is allowed, so the agent can still
/// reach the Jinn Guard control socket (anti-lockout). The denylist verdict
/// precedes path resolution, so the deny holds whether or not a real docker
/// socket is present — the test never creates or clobbers one.
#[test]
#[ignore = "requires root/CAP_BPF, BPF LSM boot param, and /usr/lib/jinnguard/jinnguard_lsm.o"]
fn test_kernel_unix_deputy_blocking_percentiles() {
    let root = fs_root("unix_deputy");
    let daemon = DaemonGuard::spawn("unix_deputy", root.to_str().unwrap());

    // Ordinary, non-denylisted unix socket the governed process may reach.
    let allowed_sock = "/tmp/jg_kernel_lsm_unix_deputy_allowed.sock";
    let _ = fs::remove_file(allowed_sock);
    let allowed_listener = UnixListener::bind(allowed_sock).unwrap();
    let (allowed_running, allowed_thread) = spawn_unix_accept_loop(allowed_listener);

    // Built-in denylisted orchestrator socket (see ORCHESTRATOR_CONTROL_SOCKETS
    // in ebpf_monitor.rs). Connecting yields EPERM from the LSM before the path
    // is resolved, so no live docker daemon is required.
    let denied_sock = "/run/docker.sock";

    let mut stats = DecisionStats::default();
    for idx in 0..operation_count() {
        if idx % 2 == 0 {
            stats.record(ExpectedDecision::Allow, || {
                UnixStream::connect(allowed_sock).map(|_| ())
            });
        } else {
            stats.record(ExpectedDecision::Deny, || {
                UnixStream::connect(denied_sock).map(|_| ())
            });
        }
    }

    finish_accept_loop(allowed_running, allowed_thread);
    stats.assert_expected_and_report("UNIX_DEPUTY_DENYLIST");
    let _ = fs::remove_file(allowed_sock);
    drop(daemon);
    let _ = fs::remove_dir_all(root);
}
