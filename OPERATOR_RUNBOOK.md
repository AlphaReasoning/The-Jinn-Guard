# Jinn Guard — Operator Runbook

Operational guide for deploying, monitoring, upgrading, and recovering a Jinn
Guard daemon. For the security model and scope see
[`THREAT_MODEL.md`](THREAT_MODEL.md); for one-command validation see
[`PROFESSOR_VALIDATION.md`](PROFESSOR_VALIDATION.md).

> **Status:** validated research prototype / controlled-pilot MVP. Validated on
> Debian / Linux 6.12. Treat any first deployment as a pilot.

---

## 1. What it is, operationally

A single daemon (`/usr/sbin/jinnguard`) runs as the unprivileged `jinnguard`
user. It listens on a Unix-domain socket for HMAC-signed *proposals* and returns
allow/deny decisions, and (when the kernel feature is built and privileges
allow) loads eBPF-LSM hooks that enforce decisions in the kernel. It is
**fail-closed** for enterprise startup and **fail-safe** for the operator (safe
mode and cgroup scoping below).

---

## 2. Paths & files

| Path | Purpose | Perms |
|---|---|---|
| `/usr/sbin/jinnguard` | Daemon binary | 0755 |
| `/etc/jinnguard/policy.yaml` | Policy (hot-reloadable) | 0640 root:jinnguard |
| `/etc/jinnguard/secret` | HMAC-SHA256 secret | 0440 root:jinnguard |
| `/usr/lib/jinnguard/lsm/*.o` | Compiled eBPF-LSM objects | 0644 |
| `/run/jinnguard/jinnguard.sock` | Governance socket | 0750 dir |
| `/var/lib/jinnguard/lineage.json(.db)` | Agent lineage state | — |
| `/var/log/jinnguard/audit.log(.db)` | Hash-chained audit log | — |
| `/etc/systemd/system/jinnguard.service` | systemd unit | 0644 |

The secret is also loaded into the kernel keyring (`keyctl ... jinnguard_hmac_key
@s`); the daemon falls back to the file if the keyring entry is absent.

---

## 3. Install

From a checkout on the target host (needs root):

```bash
cargo build --release
sudo bash deploy/install.sh        # creates user/dirs, generates secret, installs unit + binary
sudo systemctl enable --now jinnguard
```

The installer refuses to proceed if the binary lacks the `JINNGUARD_SAFE_MODE`
marker (a guard against shipping a build that cannot enter audit-only mode). To
also install kernel enforcement objects, build them (`make -C bpf`, needs
clang + bpftool) and install to `/usr/lib/jinnguard/lsm/`.

---

## 4. Configuration

### Environment variables

| Variable | Effect | Default |
|---|---|---|
| `JINNGUARD_SAFE_MODE=1` | **Audit-only**: hooks load but every decision returns allow. Nothing is blocked. | off |
| `JINNGUARD_ENTERPRISE=1` | Fail-closed: startup *requires* kernel telemetry; refuse to run degraded. | set by unit |
| `JINNGUARD_GOVERN_CGROUP=<dir>` | Confine kernel enforcement to one cgroup-v2; all other tasks pass through. | unset = global |
| `JINNGUARD_HARDEN_CAPS=1` | After BPF load: set `no_new_privs`, drop dangerous caps from the bounding set, **and** reduce the live (effective+permitted) set to the minimal `RETAINED_CAPS` via `capset(2)` (#11). | off |
| `JINNGUARD_METRICS_PORT=<port>` | Serve Prometheus metrics on `127.0.0.1:<port>/metrics`. | off |
| `JINNGUARD_OTLP_ENDPOINT=<url>` | Push OTLP/HTTP JSON metrics to `<url>`; base collector URLs get `/v1/metrics` appended. | off |
| `JINNGUARD_OTLP_INTERVAL_SECS=<n>` | OTLP metrics export interval. | `30` |
| `JINNGUARD_OTLP_TIMEOUT_SECS=<n>` | OTLP metrics request timeout. | `5` |
| `JINNGUARD_OTLP_HEADERS=k=v,...` | Optional OTLP HTTP headers; values are never logged. | unset |
| `JINNGUARD_AUDIT_SALT_MAX_AGE_SECS=<n>` | Auto-rotate the audit pseudonym salt at startup once it is older than `n` seconds (limits long-horizon pseudonym correlation). Erasure/access still cover prior epochs. | off (no rotation) |
| `JINNGUARD_SECRET_FILE=<path>` | HMAC secret file location. | `/etc/jinnguard/secret` |
| `JINNGUARD_PREVIOUS_SECRET_FILE=<path>` | Previous HMAC secret accepted during a bounded rotation grace window. Requires `JINNGUARD_PREVIOUS_SECRET_VALID_UNTIL`. | unset |
| `JINNGUARD_PREVIOUS_SECRET_VALID_UNTIL=<epoch>` | Unix epoch seconds when the previous HMAC secret stops verifying. Requires `JINNGUARD_PREVIOUS_SECRET_FILE`. | unset |
| `ENABLE_EXPLAINABILITY=1` | Verbose per-decision explanations in the log. | off |

CLI flags (set by the unit): `--socket-path --policy-file --secret-file
--previous-secret-file --previous-secret-valid-until --lineage-file --audit-log
--mcp-port`.

**MCP gateway mTLS (optional).** Pass `--mcp-tls-cert <pem>`, `--mcp-tls-key <pem>`
and `--mcp-tls-ca <pem>` *together* to require mutual TLS on the MCP gateway: the
gateway presents its certificate and only admits clients presenting a certificate
that chains to the CA bundle. Omit all three for plaintext (default). Supplying a
*partial* set is a fatal config error (`code=78 kind=MCP_TLS_CONFIG`) — the daemon
refuses to start rather than silently fall back to plaintext.

**RootAI remote semantic scorer mTLS (optional).** Pass `--rootai-url <https-url>`,
`--rootai-tls-cert <pem>`, `--rootai-tls-key <pem>` and `--rootai-tls-ca <pem>`
together to use a remote semantic scorer over HTTPS with mutual TLS. Omit all
four for the local heuristic classifier (default). Supplying a partial set is a
fatal config error (`code=78 kind=ROOTAI_TLS_CONFIG`), and `--rootai-url` is
mutually exclusive with `--rootai-socket`. Runtime scorer failures,
low-confidence responses, oversized responses, parse failures, or TLS errors fall
back to the local heuristic and do not change enforcement availability.

### Policy

`/etc/jinnguard/policy.yaml` defines agents, allowlists, denylists, quotas,
intents, the global safety ceiling, and optional `enforcement_scope`. It is
**hot-reloaded on `SIGHUP`** — no restart needed:

```bash
sudo systemctl reload jinnguard    # or: sudo kill -HUP $(pidof jinnguard)
```

> Anti-lockout guard: base-system path prefixes are rejected at policy install
> and re-excluded at lookup, so a bad policy cannot place the operator's own
> system paths under governance.

Per-agent identity binding is optional but recommended on shared hosts. Add
`allowed_peer_uids` under an `agent_nodes` entry to bind that signed `agent_id`
to the Unix users observed via `SO_PEERCRED`:

```yaml
agent_nodes:
  - id: "locked_agent_dev_01"
    privilege_tier: 1
    allowed_peer_uids:
      - 10001
```

If the field is empty or omitted, legacy shared-key behavior is preserved. If a
caller signs as that `agent_id` from any other UID, the daemon returns
`DENY_AGENT_IDENTITY_BINDING`.

---

## 5. Operating modes

- **Audit-only (safe mode):** `JINNGUARD_SAFE_MODE=1`. Hooks observe and log but
  block nothing. Use this for first bring-up on any host you care about.
- **Enforcement:** safe mode off. The kernel actually denies. **Scope it** with
  `JINNGUARD_GOVERN_CGROUP` so only the agent's cgroup is governed and the host
  session is never affected. Global enforcement (scope unset) governs every
  process — only do that on a dedicated host.

---

## 6. Start / stop / status

```bash
sudo systemctl start|stop|restart jinnguard
sudo systemctl reload jinnguard          # SIGHUP: hot-reload policy only
systemctl status jinnguard
journalctl -u jinnguard -f               # live logs
```

---

## 7. Monitoring & health

### Prometheus metrics (opt-in)

Set `JINNGUARD_METRICS_PORT` (e.g. add `Environment=JINNGUARD_METRICS_PORT=9095`
to the unit). Endpoint is **loopback-only**; expose externally via a reverse
proxy if needed.

```bash
curl -s 127.0.0.1:9095/metrics
curl -s 127.0.0.1:9095/healthz          # "ok"
```

Key series:

| Metric | Meaning |
|---|---|
| `jinnguard_uptime_seconds` | Daemon uptime |
| `jinnguard_proposals_total` | Proposals received |
| `jinnguard_decisions_total{verdict}` | Userspace allow/deny |
| `jinnguard_denials_total{reason}` | Denials by reason (e.g. `DENY_REPLAY_ATTACK`) |
| `jinnguard_kernel_decisions_total{verdict}` | Kernel-LSM allow/deny |
| `jinnguard_orchestrator_socket_attempts_total{orchestrator,verdict}` | Governed connects to orchestrator/init sockets (confused-deputy signal) |
| `jinnguard_audit_chain_entries` | Entries in the tamper-evident audit chain |
| `jinnguard_audit_chain_intact` | Last `verify_chain` result (1 = tamper-evidence holds) |
| `jinnguard_audit_salt_epoch` | Active pseudonym-salt epoch (increments on rotation) |
| `jinnguard_audit_erasures_total` / `jinnguard_audit_erased_rows_total` | Honoured Art. 17 erasures (accountability) |
| `jinnguard_build_info{version}` | Build version |

### OTLP metrics export (opt-in)

Set `JINNGUARD_OTLP_ENDPOINT` to push the same metrics to an OTLP/HTTP collector.
The exporter uses JSON-encoded OTLP protobuf payloads and `Content-Type:
application/json`; no telemetry leaves the host unless this endpoint is set.

```bash
Environment=JINNGUARD_OTLP_ENDPOINT=http://127.0.0.1:4318
Environment=JINNGUARD_OTLP_INTERVAL_SECS=30
```

Standard OpenTelemetry endpoint variables are also accepted:
`OTEL_EXPORTER_OTLP_METRICS_ENDPOINT` is used as an exact metrics URL, and
`OTEL_EXPORTER_OTLP_ENDPOINT` is treated as a base URL with `/v1/metrics`
appended.

Suggested alerts: daemon down (`up == 0` / no `uptime` scrape), a sudden spike in
`jinnguard_denials_total`, any rise in a `DENY_REPLAY_ATTACK` series, any
`jinnguard_orchestrator_socket_attempts_total{verdict="allow"}` (a confused-deputy
path is open), and **`jinnguard_audit_chain_intact == 0`** (audit tamper-evidence
broken — page immediately).

### Health checks

- `systemctl is-active jinnguard` → `active`
- Socket present: `test -S /run/jinnguard/jinnguard.sock`
- `journalctl -u jinnguard | grep "JINN GUARD ACTIVE"` after start.

### Audit log

`/var/log/jinnguard/audit.log` is hash-chained (tamper-evident). Ship it to your
log pipeline; back it up before rotation (§10).

---

## 8. Upgrade

```bash
# 1. Build + stage the new binary
cargo build --release
# 2. Quick pre-flight: the new binary must support safe mode
grep -aq JINNGUARD_SAFE_MODE target/release/ts_cli || { echo "ABORT: bad build"; exit 1; }
# 3. Swap and restart
sudo install -m0755 target/release/ts_cli /usr/sbin/jinnguard
sudo systemctl restart jinnguard
# 4. Verify
systemctl is-active jinnguard && journalctl -u jinnguard -n20 --no-pager
```

If kernel objects changed, rebuild + reinstall them (`make -C bpf`,
`/usr/lib/jinnguard/lsm/`) before restart. The daemon clears any stale pinned
ring buffer on startup, so a restart is safe.

---

## 9. Rollback

```bash
# Keep the previous binary as /usr/sbin/jinnguard.prev during upgrades.
sudo install -m0755 /usr/sbin/jinnguard.prev /usr/sbin/jinnguard
sudo systemctl restart jinnguard
```

Policy rollback: restore the previous `policy.yaml` and `systemctl reload`.
Kernel state never persists across reboot, so a reboot is always a clean slate.

---

## 10. Incident response

### Disable enforcement FAST (no lockout)

Enforcement only exists while the daemon is alive and (for kernel denial) hooks
are attached. To stop blocking immediately, in order of preference:

```bash
# 1. Drop to audit-only and reload (blocks nothing, keeps observability)
sudo systemctl set-environment JINNGUARD_SAFE_MODE=1   # or edit the unit
sudo systemctl restart jinnguard

# 2. Or stop the daemon entirely — kernel hooks detach when it exits
sudo systemctl stop jinnguard

# 3. Last resort — reboot. bpffs is wiped on boot; nothing re-arms unless the
#    service is enabled, so consider `systemctl disable jinnguard` first.
sudo systemctl disable jinnguard && sudo reboot
```

Notes:
- Kernel enforcement is **cgroup-scoped** when `JINNGUARD_GOVERN_CGROUP` is set,
  so the operator session is structurally out of scope and a reboot is rarely
  needed.
- `SIGKILL` to the daemon is delivered by the kernel and is **not** subject to
  the execve hook, so you can always kill the process even under global
  enforcement.

### Suspected key compromise

Rotate the HMAC secret with a bounded grace window:

```bash
sudo install -o root -g jinnguard -m 0440 /etc/jinnguard/secret /etc/jinnguard/secret.previous
sudo install -o root -g jinnguard -m 0440 /dev/null /etc/jinnguard/secret.next
sudo sh -c 'openssl rand -hex 32 > /etc/jinnguard/secret.next'
sudo mv /etc/jinnguard/secret.next /etc/jinnguard/secret
sudo keyctl padd user jinnguard_hmac_key @s < /etc/jinnguard/secret
```

Set `JINNGUARD_PREVIOUS_SECRET_FILE=/etc/jinnguard/secret.previous` and
`JINNGUARD_PREVIOUS_SECRET_VALID_UNTIL=<unix-epoch-seconds>` in the service
environment, update clients to sign with the new current key, then restart. The
daemon accepts the previous key only until that epoch and logs
`accepted previous HMAC key during rotation grace` for old-key proposals. After
the grace window, remove the previous-key environment and
`/etc/jinnguard/secret.previous`, then restart again. Partial rotation config,
empty keys, or identical current/previous keys are fatal startup config errors.

---

## 11. Troubleshooting

### Exit codes (machine-parseable)

On a startup failure the daemon prints `jinnguard: fatal code=<n> kind=<KIND>
msg="..."` and exits:

| Code | Kind | Cause / fix |
|---|---|---|
| 78 | `SECRET_MISSING` | No HMAC secret. Provide `--secret-file` or load the keyring key. |
| 78 | `SECRET_ROTATION_CONFIG` | Invalid HMAC rotation state: set previous secret path + expiry together, ensure both keys are non-empty and different. |
| 69 | `KERNEL_LSM_UNAVAILABLE` | Enterprise startup required kernel telemetry but the LSM load failed (no BPF-LSM, missing `/usr/lib/jinnguard/lsm/*.o`, or insufficient caps). |
| 70 | `STARTUP_FAILED` | Other startup error; see the message + `journalctl`. |

### Common issues

| Symptom | Likely cause | Action |
|---|---|---|
| Daemon exits 69 at start | BPF-LSM not enabled / objects missing | `cat /sys/kernel/security/lsm \| grep bpf`; install LSM objects; or run without `JINNGUARD_ENTERPRISE`. |
| Hooks load but **no** telemetry events | Stale pinned ring buffer | Already auto-cleared on startup; if persistent, `rm /sys/fs/bpf/requests` and restart. |
| `verifier` error on load | Kernel/BTF mismatch | Regenerate `vmlinux.h` from the host BTF and rebuild the objects. |
| Everything denied unexpectedly | Global enforcement with a tight allowlist | Set `JINNGUARD_GOVERN_CGROUP`, or `JINNGUARD_SAFE_MODE=1` to confirm, then fix policy. |
| Proposals rejected after a secret change | Key mismatch or expired previous-key grace | Ensure clients sign with the current key, or set previous key + valid-until during a planned rotation. |

---

## 12. Backup & retention

- **Audit log** (`/var/log/jinnguard/audit.log`): hash-chained; archive before
  rotation to preserve the chain.
- **Lineage DB** (`/var/lib/jinnguard/lineage.*`): per-agent sequence/replay
  state; back up with the audit log so restored state stays consistent.
- **Config** (`/etc/jinnguard/policy.yaml`, secret): keep in your secrets/config
  management; the secret is sensitive (HMAC key).
