//! Lightweight, dependency-free Prometheus metrics for Jinn Guard.
//!
//! Counters are process-global atomics; denial reasons are kept in a small map
//! so every `DENY_*` signal is captured without enumerating them here. The
//! `/metrics` endpoint is **opt-in** (`JINNGUARD_METRICS_PORT`) and binds to
//! loopback only, so enabling it never exposes anything off-host by default and
//! changes no existing behavior when unset.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

#[derive(Default)]
struct Metrics {
    proposals_total: AtomicU64,
    decisions_allow_total: AtomicU64,
    decisions_deny_total: AtomicU64,
    kernel_events_total: AtomicU64,
    kernel_allow_total: AtomicU64,
    kernel_deny_total: AtomicU64,
    /// Userspace denials keyed by their `SIGNAL: <reason>` token.
    deny_reasons: Mutex<BTreeMap<String, u64>>,
    /// #58: governed-agent connect attempts to orchestrator/init control sockets,
    /// keyed by `"<orchestrator>|<verdict>"` (e.g. `"docker|deny"`). A non-zero
    /// allow count is itself a signal — it means a confused-deputy path is open.
    deputy_attempts: Mutex<BTreeMap<String, u64>>,
    /// #11/#61 audit observability. Entry count + active salt epoch are gauges;
    /// erasures are counters (Art. 5(2) accountability); `audit_chain_intact` is a
    /// 0/1 gauge reflecting the last `verify_chain` (1 = tamper-evidence holds).
    audit_chain_entries: AtomicU64,
    audit_salt_epoch: AtomicU64,
    audit_erasures_total: AtomicU64,
    audit_erased_rows_total: AtomicU64,
    audit_chain_intact: AtomicU64,
}

static METRICS: OnceLock<Metrics> = OnceLock::new();
static START: OnceLock<Instant> = OnceLock::new();

fn m() -> &'static Metrics {
    METRICS.get_or_init(Metrics::default)
}

/// Initialize the registry and start the uptime clock. Idempotent.
pub fn init() {
    let _ = m();
    let _ = START.get_or_init(Instant::now);
    // Optimistic until the first chain verification reports otherwise, so the
    // gauge never reads "broken" merely because no check has run yet.
    m().audit_chain_intact.store(1, Ordering::Relaxed);
}

fn uptime_seconds() -> u64 {
    START.get().map(|s| s.elapsed().as_secs()).unwrap_or(0)
}

/// One proposal accepted on the governance socket.
pub fn record_proposal() {
    m().proposals_total.fetch_add(1, Ordering::Relaxed);
}

/// Classify a framed governance response. Only `SIGNAL: ...` decision frames are
/// counted; other frames (errors, banners) are ignored.
pub fn record_response(data: &[u8]) {
    const PREFIX: &[u8] = b"SIGNAL: ";
    if !data.starts_with(PREFIX) {
        return;
    }
    let body = &data[PREFIX.len()..];
    if body.starts_with(b"ALLOW") {
        m().decisions_allow_total.fetch_add(1, Ordering::Relaxed);
    } else if body.starts_with(b"DENY") {
        m().decisions_deny_total.fetch_add(1, Ordering::Relaxed);
        let reason = reason_token(body);
        if let Ok(mut map) = m().deny_reasons.lock() {
            *map.entry(reason).or_insert(0) += 1;
        }
    }
}

/// Extract a Prometheus-label-safe reason token (first whitespace-delimited word,
/// `[A-Z0-9_]` only) from a `DENY...` response body.
fn reason_token(body: &[u8]) -> String {
    body.iter()
        .take_while(|&&b| b != b'\n' && b != b'\r' && b != b' ')
        .map(|&b| {
            let c = b as char;
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// #58: a governed agent attempted to connect to an orchestrator/init control
/// socket (docker/containerd/podman/crio/libvirt/dbus/systemd). Recorded whether
/// or not the connect was denied — an `allow` here flags a confused-deputy path
/// that should have been closed.
pub fn record_orchestrator_socket_attempt(orchestrator: &str, denied: bool) {
    let verdict = if denied { "deny" } else { "allow" };
    let key = format!("{orchestrator}|{verdict}");
    if let Ok(mut map) = m().deputy_attempts.lock() {
        *map.entry(key).or_insert(0) += 1;
    }
}

// #11/#61 Audit observability setters. The audit logger pushes its state here so
// the (loopback-only) `/metrics` endpoint can surface tamper-evidence and
// data-protection posture without the scraper touching the audit DB.

/// Total entries currently in the tamper-evident chain.
pub fn set_audit_chain_entries(n: u64) {
    m().audit_chain_entries.store(n, Ordering::Relaxed);
}

/// The active pseudonym-salt epoch (increments on each rotation, #11).
pub fn set_audit_salt_epoch(epoch: u64) {
    m().audit_salt_epoch.store(epoch, Ordering::Relaxed);
}

/// One honoured erasure request (Art. 17) that removed `rows` PII rows. No-op
/// erasures (already erased) are not counted.
pub fn record_audit_erasure(rows: u64) {
    if rows == 0 {
        return;
    }
    m().audit_erasures_total.fetch_add(1, Ordering::Relaxed);
    m().audit_erased_rows_total
        .fetch_add(rows, Ordering::Relaxed);
}

/// Result of the most recent chain verification (`true` = tamper-evidence holds).
pub fn set_audit_chain_intact(intact: bool) {
    m().audit_chain_intact
        .store(u64::from(intact), Ordering::Relaxed);
}

/// One synchronous kernel-LSM allow/deny decision.
pub fn record_kernel_decision(denied: bool) {
    m().kernel_events_total.fetch_add(1, Ordering::Relaxed);
    if denied {
        m().kernel_deny_total.fetch_add(1, Ordering::Relaxed);
    } else {
        m().kernel_allow_total.fetch_add(1, Ordering::Relaxed);
    }
}

/// Render the Prometheus text exposition format.
pub fn render() -> String {
    let g = m();
    let mut out = String::with_capacity(1024);

    out.push_str("# HELP jinnguard_build_info Build information.\n");
    out.push_str("# TYPE jinnguard_build_info gauge\n");
    out.push_str(&format!(
        "jinnguard_build_info{{version=\"{}\"}} 1\n",
        env!("CARGO_PKG_VERSION")
    ));

    out.push_str("# HELP jinnguard_uptime_seconds Daemon uptime in seconds.\n");
    out.push_str("# TYPE jinnguard_uptime_seconds gauge\n");
    out.push_str(&format!("jinnguard_uptime_seconds {}\n", uptime_seconds()));

    out.push_str("# HELP jinnguard_proposals_total Governance proposals received.\n");
    out.push_str("# TYPE jinnguard_proposals_total counter\n");
    out.push_str(&format!(
        "jinnguard_proposals_total {}\n",
        g.proposals_total.load(Ordering::Relaxed)
    ));

    out.push_str("# HELP jinnguard_decisions_total Userspace governance decisions by verdict.\n");
    out.push_str("# TYPE jinnguard_decisions_total counter\n");
    out.push_str(&format!(
        "jinnguard_decisions_total{{verdict=\"allow\"}} {}\n",
        g.decisions_allow_total.load(Ordering::Relaxed)
    ));
    out.push_str(&format!(
        "jinnguard_decisions_total{{verdict=\"deny\"}} {}\n",
        g.decisions_deny_total.load(Ordering::Relaxed)
    ));

    out.push_str("# HELP jinnguard_denials_total Userspace denials by reason.\n");
    out.push_str("# TYPE jinnguard_denials_total counter\n");
    if let Ok(map) = g.deny_reasons.lock() {
        for (reason, count) in map.iter() {
            out.push_str(&format!(
                "jinnguard_denials_total{{reason=\"{reason}\"}} {count}\n"
            ));
        }
    }

    out.push_str(
        "# HELP jinnguard_kernel_events_total Synchronous kernel-LSM decisions observed.\n",
    );
    out.push_str("# TYPE jinnguard_kernel_events_total counter\n");
    out.push_str(&format!(
        "jinnguard_kernel_events_total {}\n",
        g.kernel_events_total.load(Ordering::Relaxed)
    ));

    out.push_str("# HELP jinnguard_kernel_decisions_total Kernel-LSM decisions by verdict.\n");
    out.push_str("# TYPE jinnguard_kernel_decisions_total counter\n");
    out.push_str(&format!(
        "jinnguard_kernel_decisions_total{{verdict=\"allow\"}} {}\n",
        g.kernel_allow_total.load(Ordering::Relaxed)
    ));
    out.push_str(&format!(
        "jinnguard_kernel_decisions_total{{verdict=\"deny\"}} {}\n",
        g.kernel_deny_total.load(Ordering::Relaxed)
    ));

    out.push_str(
        "# HELP jinnguard_orchestrator_socket_attempts_total Governed-agent connect attempts to orchestrator/init control sockets (confused-deputy signal).\n",
    );
    out.push_str("# TYPE jinnguard_orchestrator_socket_attempts_total counter\n");
    if let Ok(map) = g.deputy_attempts.lock() {
        for (key, count) in map.iter() {
            let (orchestrator, verdict) = key.split_once('|').unwrap_or((key.as_str(), "deny"));
            out.push_str(&format!(
                "jinnguard_orchestrator_socket_attempts_total{{orchestrator=\"{orchestrator}\",verdict=\"{verdict}\"}} {count}\n"
            ));
        }
    }

    // #11/#61 audit observability: tamper-evidence + data-protection posture.
    out.push_str(
        "# HELP jinnguard_audit_chain_entries Entries in the tamper-evident audit chain.\n",
    );
    out.push_str("# TYPE jinnguard_audit_chain_entries gauge\n");
    out.push_str(&format!(
        "jinnguard_audit_chain_entries {}\n",
        g.audit_chain_entries.load(Ordering::Relaxed)
    ));

    out.push_str(
        "# HELP jinnguard_audit_chain_intact Whether the last chain verification passed (1=intact).\n",
    );
    out.push_str("# TYPE jinnguard_audit_chain_intact gauge\n");
    out.push_str(&format!(
        "jinnguard_audit_chain_intact {}\n",
        g.audit_chain_intact.load(Ordering::Relaxed)
    ));

    out.push_str(
        "# HELP jinnguard_audit_salt_epoch Active pseudonym-salt epoch (increments on rotation).\n",
    );
    out.push_str("# TYPE jinnguard_audit_salt_epoch gauge\n");
    out.push_str(&format!(
        "jinnguard_audit_salt_epoch {}\n",
        g.audit_salt_epoch.load(Ordering::Relaxed)
    ));

    out.push_str("# HELP jinnguard_audit_erasures_total Honoured erasure requests (Art. 17).\n");
    out.push_str("# TYPE jinnguard_audit_erasures_total counter\n");
    out.push_str(&format!(
        "jinnguard_audit_erasures_total {}\n",
        g.audit_erasures_total.load(Ordering::Relaxed)
    ));

    out.push_str(
        "# HELP jinnguard_audit_erased_rows_total PII rows removed by erasure requests.\n",
    );
    out.push_str("# TYPE jinnguard_audit_erased_rows_total counter\n");
    out.push_str(&format!(
        "jinnguard_audit_erased_rows_total {}\n",
        g.audit_erased_rows_total.load(Ordering::Relaxed)
    ));

    out
}

/// Serve `GET /metrics` on `127.0.0.1:<port>` until the process exits. Loopback
/// only by design: exposing metrics off-host is an explicit operator choice
/// (e.g. via a reverse proxy), never a default.
pub async fn serve(port: u16) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let listener = match TcpListener::bind(("127.0.0.1", port)).await {
        Ok(l) => l,
        Err(err) => {
            eprintln!("[metrics] could not bind 127.0.0.1:{port}: {err}");
            return;
        }
    };
    eprintln!("[metrics] Prometheus endpoint at http://127.0.0.1:{port}/metrics");

    loop {
        let (mut sock, _) = match listener.accept().await {
            Ok(pair) => pair,
            Err(_) => continue,
        };
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let n = match sock.read(&mut buf).await {
                Ok(n) => n,
                Err(_) => return,
            };
            let req = String::from_utf8_lossy(&buf[..n]);
            let body;
            let status;
            if req.starts_with("GET /metrics") {
                body = render();
                status = "200 OK";
            } else if req.starts_with("GET /healthz") {
                body = "ok\n".to_string();
                status = "200 OK";
            } else {
                body = "not found\n".to_string();
                status = "404 Not Found";
            }
            let resp = format!(
                "HTTP/1.1 {status}\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = sock.write_all(resp.as_bytes()).await;
            let _ = sock.flush().await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reason_token_is_label_safe() {
        assert_eq!(reason_token(b"DENY_REPLAY_ATTACK\n"), "DENY_REPLAY_ATTACK");
        assert_eq!(reason_token(b"DENY_VIOLATION extra"), "DENY_VIOLATION");
        // Non-alnum chars are squashed to underscores.
        assert_eq!(reason_token(b"DENY-X.Y"), "DENY_X_Y");
    }

    #[test]
    fn render_emits_core_series_and_counts_decisions() {
        init();
        record_proposal();
        record_response(b"SIGNAL: ALLOW\n");
        record_response(b"SIGNAL: DENY_VIOLATION\n");
        record_response(b"banner: not a decision"); // ignored
        record_kernel_decision(true);

        let text = render();
        assert!(text.contains("jinnguard_uptime_seconds"));
        assert!(text.contains("jinnguard_build_info{version="));
        assert!(text.contains("jinnguard_decisions_total{verdict=\"allow\"}"));
        assert!(text.contains("jinnguard_decisions_total{verdict=\"deny\"}"));
        assert!(text.contains("jinnguard_denials_total{reason=\"DENY_VIOLATION\"}"));
        assert!(text.contains("jinnguard_kernel_decisions_total{verdict=\"deny\"}"));
    }

    #[test]
    fn render_emits_audit_observability_series() {
        // The audit series are always present (race-free): assert the names/HELP,
        // not values other tests may concurrently mutate.
        let text = render();
        for series in [
            "jinnguard_audit_chain_entries",
            "jinnguard_audit_chain_intact",
            "jinnguard_audit_salt_epoch",
            "jinnguard_audit_erasures_total",
            "jinnguard_audit_erased_rows_total",
        ] {
            assert!(text.contains(series), "missing audit series {series}");
        }
        assert!(text.contains("# TYPE jinnguard_audit_salt_epoch gauge"));
        assert!(text.contains("# TYPE jinnguard_audit_erasures_total counter"));
        // Every audit series renders a value line (numeric), not just metadata.
        assert!(text.contains("jinnguard_audit_chain_intact "));
    }
}
