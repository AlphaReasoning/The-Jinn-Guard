//! Lightweight Prometheus and OTLP metrics for Jinn Guard.
//!
//! Counters are process-global atomics; denial reasons are kept in a small map
//! so every `DENY_*` signal is captured without enumerating them here. The
//! `/metrics` endpoint is **opt-in** (`JINNGUARD_METRICS_PORT`) and binds to
//! loopback only, so enabling it never exposes anything off-host by default and
//! changes no existing behavior when unset. OTLP/HTTP export is also opt-in
//! (`JINNGUARD_OTLP_ENDPOINT` or `OTEL_EXPORTER_OTLP_*`) and uses JSON-encoded
//! OTLP protobuf payloads over the already-present `reqwest` dependency.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

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
static START_UNIX_NANO: OnceLock<u64> = OnceLock::new();

fn m() -> &'static Metrics {
    METRICS.get_or_init(Metrics::default)
}

/// Initialize the registry and start the uptime clock. Idempotent.
pub fn init() {
    let _ = m();
    let _ = START.get_or_init(Instant::now);
    let _ = START_UNIX_NANO.get_or_init(now_unix_nano);
    // Optimistic until the first chain verification reports otherwise, so the
    // gauge never reads "broken" merely because no check has run yet.
    m().audit_chain_intact.store(1, Ordering::Relaxed);
}

fn now_unix_nano() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .min(u128::from(u64::MAX)) as u64
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OtlpConfig {
    pub endpoint: String,
    pub interval: Duration,
    pub timeout: Duration,
    pub headers: Vec<(String, String)>,
}

impl OtlpConfig {
    fn from_env() -> Option<Self> {
        let (endpoint, append_metrics_path) =
            if let Ok(value) = std::env::var("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT") {
                (value, false)
            } else if let Ok(value) = std::env::var("JINNGUARD_OTLP_ENDPOINT") {
                (value, true)
            } else if let Ok(value) = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT") {
                (value, true)
            } else {
                return None;
            };

        let interval = if let Some(secs) = parse_env_u64("JINNGUARD_OTLP_INTERVAL_SECS") {
            Duration::from_secs(secs.max(1))
        } else if let Some(ms) = parse_env_u64("OTEL_METRIC_EXPORT_INTERVAL") {
            Duration::from_millis(ms.max(1_000))
        } else {
            Duration::from_secs(30)
        };
        let timeout_secs = parse_env_u64("JINNGUARD_OTLP_TIMEOUT_SECS")
            .map(|secs| secs.max(1))
            .unwrap_or(5);
        let headers = std::env::var("JINNGUARD_OTLP_HEADERS")
            .or_else(|_| std::env::var("OTEL_EXPORTER_OTLP_HEADERS"))
            .map(|raw| parse_otlp_headers(&raw))
            .unwrap_or_default();

        Some(Self {
            endpoint: normalize_otlp_endpoint(&endpoint, append_metrics_path),
            interval,
            timeout: Duration::from_secs(timeout_secs),
            headers,
        })
    }
}

pub fn otlp_config_from_env() -> Option<OtlpConfig> {
    OtlpConfig::from_env()
}

fn parse_env_u64(name: &str) -> Option<u64> {
    std::env::var(name).ok()?.parse::<u64>().ok()
}

fn normalize_otlp_endpoint(endpoint: &str, append_metrics_path: bool) -> String {
    let trimmed = endpoint.trim().trim_end_matches('/');
    if !append_metrics_path || trimmed.ends_with("/v1/metrics") {
        trimmed.to_string()
    } else {
        format!("{trimmed}/v1/metrics")
    }
}

fn parse_otlp_headers(raw: &str) -> Vec<(String, String)> {
    raw.split(',')
        .filter_map(|entry| {
            let (key, value) = entry.split_once('=')?;
            let key = key.trim();
            if key.is_empty() {
                return None;
            }
            Some((key.to_string(), value.trim().to_string()))
        })
        .collect()
}

fn otlp_attr(key: &str, value: impl Into<String>) -> Value {
    json!({
        "key": key,
        "value": { "stringValue": value.into() }
    })
}

fn otlp_data_point(
    value: u64,
    attrs: Vec<Value>,
    start_unix_nano: u64,
    time_unix_nano: u64,
) -> Value {
    json!({
        "attributes": attrs,
        "startTimeUnixNano": start_unix_nano.to_string(),
        "timeUnixNano": time_unix_nano.to_string(),
        "asInt": value.to_string(),
    })
}

fn otlp_sum_metric(name: &str, description: &str, points: Vec<Value>, monotonic: bool) -> Value {
    json!({
        "name": name,
        "description": description,
        "unit": "1",
        "sum": {
            "aggregationTemporality": 2,
            "isMonotonic": monotonic,
            "dataPoints": points,
        }
    })
}

fn otlp_gauge_metric(name: &str, description: &str, points: Vec<Value>) -> Value {
    json!({
        "name": name,
        "description": description,
        "unit": "1",
        "gauge": { "dataPoints": points }
    })
}

/// Render the current metrics as an OTLP/HTTP JSON ExportMetricsServiceRequest.
pub fn render_otlp_json() -> Value {
    init();
    let g = m();
    let start = *START_UNIX_NANO.get_or_init(now_unix_nano);
    let now = now_unix_nano();
    let mut metrics = Vec::new();

    let point = |value, attrs| otlp_data_point(value, attrs, start, now);

    metrics.push(otlp_gauge_metric(
        "jinnguard_build_info",
        "Build information.",
        vec![point(
            1,
            vec![otlp_attr("version", env!("CARGO_PKG_VERSION"))],
        )],
    ));
    metrics.push(otlp_gauge_metric(
        "jinnguard_uptime_seconds",
        "Daemon uptime in seconds.",
        vec![point(uptime_seconds(), vec![])],
    ));
    metrics.push(otlp_sum_metric(
        "jinnguard_proposals_total",
        "Governance proposals received.",
        vec![point(g.proposals_total.load(Ordering::Relaxed), vec![])],
        true,
    ));
    metrics.push(otlp_sum_metric(
        "jinnguard_decisions_total",
        "Userspace governance decisions by verdict.",
        vec![
            point(
                g.decisions_allow_total.load(Ordering::Relaxed),
                vec![otlp_attr("verdict", "allow")],
            ),
            point(
                g.decisions_deny_total.load(Ordering::Relaxed),
                vec![otlp_attr("verdict", "deny")],
            ),
        ],
        true,
    ));

    let mut denial_points = Vec::new();
    if let Ok(map) = g.deny_reasons.lock() {
        for (reason, count) in map.iter() {
            denial_points.push(point(*count, vec![otlp_attr("reason", reason)]));
        }
    }
    metrics.push(otlp_sum_metric(
        "jinnguard_denials_total",
        "Userspace denials by reason.",
        denial_points,
        true,
    ));

    metrics.push(otlp_sum_metric(
        "jinnguard_kernel_events_total",
        "Synchronous kernel-LSM decisions observed.",
        vec![point(g.kernel_events_total.load(Ordering::Relaxed), vec![])],
        true,
    ));
    metrics.push(otlp_sum_metric(
        "jinnguard_kernel_decisions_total",
        "Kernel-LSM decisions by verdict.",
        vec![
            point(
                g.kernel_allow_total.load(Ordering::Relaxed),
                vec![otlp_attr("verdict", "allow")],
            ),
            point(
                g.kernel_deny_total.load(Ordering::Relaxed),
                vec![otlp_attr("verdict", "deny")],
            ),
        ],
        true,
    ));

    let mut deputy_points = Vec::new();
    if let Ok(map) = g.deputy_attempts.lock() {
        for (key, count) in map.iter() {
            let (orchestrator, verdict) = key.split_once('|').unwrap_or((key.as_str(), "deny"));
            deputy_points.push(point(
                *count,
                vec![
                    otlp_attr("orchestrator", orchestrator),
                    otlp_attr("verdict", verdict),
                ],
            ));
        }
    }
    metrics.push(otlp_sum_metric(
        "jinnguard_orchestrator_socket_attempts_total",
        "Governed-agent connect attempts to orchestrator/init control sockets.",
        deputy_points,
        true,
    ));

    metrics.push(otlp_gauge_metric(
        "jinnguard_audit_chain_entries",
        "Entries in the tamper-evident audit chain.",
        vec![point(g.audit_chain_entries.load(Ordering::Relaxed), vec![])],
    ));
    metrics.push(otlp_gauge_metric(
        "jinnguard_audit_chain_intact",
        "Whether the last chain verification passed (1=intact).",
        vec![point(g.audit_chain_intact.load(Ordering::Relaxed), vec![])],
    ));
    metrics.push(otlp_gauge_metric(
        "jinnguard_audit_salt_epoch",
        "Active pseudonym-salt epoch.",
        vec![point(g.audit_salt_epoch.load(Ordering::Relaxed), vec![])],
    ));
    metrics.push(otlp_sum_metric(
        "jinnguard_audit_erasures_total",
        "Honoured erasure requests.",
        vec![point(
            g.audit_erasures_total.load(Ordering::Relaxed),
            vec![],
        )],
        true,
    ));
    metrics.push(otlp_sum_metric(
        "jinnguard_audit_erased_rows_total",
        "PII rows removed by erasure requests.",
        vec![point(
            g.audit_erased_rows_total.load(Ordering::Relaxed),
            vec![],
        )],
        true,
    ));

    json!({
        "resourceMetrics": [{
            "resource": {
                "attributes": [
                    otlp_attr("service.name", "jinnguard"),
                    otlp_attr("service.version", env!("CARGO_PKG_VERSION")),
                ]
            },
            "scopeMetrics": [{
                "scope": {
                    "name": "jinnguard.metrics",
                    "version": env!("CARGO_PKG_VERSION"),
                },
                "metrics": metrics,
            }]
        }]
    })
}

async fn export_otlp_once(client: &reqwest::Client, config: &OtlpConfig) -> Result<(), String> {
    let mut req = client
        .post(&config.endpoint)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .json(&render_otlp_json());

    for (key, value) in &config.headers {
        let name = reqwest::header::HeaderName::from_bytes(key.as_bytes())
            .map_err(|err| format!("invalid OTLP header name {key:?}: {err}"))?;
        let value = reqwest::header::HeaderValue::from_str(value)
            .map_err(|err| format!("invalid OTLP header value for {key:?}: {err}"))?;
        req = req.header(name, value);
    }

    let response = req
        .send()
        .await
        .map_err(|err| format!("OTLP export failed: {err}"))?;
    if response.status().is_success() {
        Ok(())
    } else {
        Err(format!("OTLP export returned HTTP {}", response.status()))
    }
}

/// Periodically export metrics to an OTLP/HTTP JSON endpoint. Errors are logged
/// and do not affect governance decisions or local Prometheus metrics.
pub async fn serve_otlp(config: OtlpConfig) {
    let client = match reqwest::Client::builder().timeout(config.timeout).build() {
        Ok(client) => client,
        Err(err) => {
            eprintln!("[metrics] could not create OTLP HTTP client: {err}");
            return;
        }
    };
    eprintln!(
        "[metrics] OTLP/HTTP JSON exporter enabled: endpoint={} interval={}s timeout={}s",
        config.endpoint,
        config.interval.as_secs(),
        config.timeout.as_secs()
    );
    loop {
        if let Err(err) = export_otlp_once(&client, &config).await {
            eprintln!("[metrics] {err}");
        }
        tokio::time::sleep(config.interval).await;
    }
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

    #[test]
    fn otlp_endpoint_normalization_and_headers_are_operator_friendly() {
        assert_eq!(
            normalize_otlp_endpoint("http://127.0.0.1:4318", true),
            "http://127.0.0.1:4318/v1/metrics"
        );
        assert_eq!(
            normalize_otlp_endpoint("http://127.0.0.1:4318/v1/metrics", true),
            "http://127.0.0.1:4318/v1/metrics"
        );
        assert_eq!(
            normalize_otlp_endpoint("http://collector/custom", false),
            "http://collector/custom"
        );
        assert_eq!(
            parse_otlp_headers("Authorization=Bearer abc, x-scope = prod "),
            vec![
                ("Authorization".to_string(), "Bearer abc".to_string()),
                ("x-scope".to_string(), "prod".to_string()),
            ]
        );
    }

    #[test]
    fn render_otlp_json_emits_core_metrics_payload() {
        init();
        record_proposal();
        record_response(b"SIGNAL: DENY_RUNTIME_POLICY\n");
        record_kernel_decision(false);
        record_orchestrator_socket_attempt("docker", true);
        set_audit_chain_entries(7);

        let payload = render_otlp_json();
        let metrics = payload["resourceMetrics"][0]["scopeMetrics"][0]["metrics"]
            .as_array()
            .expect("OTLP metrics array");

        let names: Vec<&str> = metrics
            .iter()
            .filter_map(|metric| metric["name"].as_str())
            .collect();
        for expected in [
            "jinnguard_proposals_total",
            "jinnguard_decisions_total",
            "jinnguard_kernel_decisions_total",
            "jinnguard_orchestrator_socket_attempts_total",
            "jinnguard_audit_chain_entries",
        ] {
            assert!(names.contains(&expected), "missing OTLP metric {expected}");
        }

        let proposals = metrics
            .iter()
            .find(|metric| metric["name"] == "jinnguard_proposals_total")
            .expect("proposals metric");
        let point = &proposals["sum"]["dataPoints"][0];
        assert!(
            point["asInt"].as_str().is_some(),
            "OTLP JSON 64-bit integers must be strings"
        );
        assert_eq!(proposals["sum"]["isMonotonic"], true);
    }
}
