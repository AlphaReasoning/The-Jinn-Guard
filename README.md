# 🛡️ Jinn Guard — Enterprise Semantic Firewall

[![CI](https://github.com/AlphaReasoning/The-Jinn-Guard/actions/workflows/ci.yml/badge.svg)](https://github.com/AlphaReasoning/The-Jinn-Guard/actions/workflows/ci.yml)

**Jinn Guard** is an asynchronous, kernel-aware semantic firewall designed to enforce mathematical safety constraints on autonomous AI agents before any tool execution is permitted. It intercepts high-level natural language intents and processes them through a lifetime-anchored **Z3 SMT solver pipeline** — verifying state transitions and risk ceilings against formalized compliance models before granting or denying execution authority.

Operating locally over high-throughput **UNIX domain sockets** on AlphaOS, the platform binds user-space proxy validation with low-level **eBPF kernel telemetry** and namespace tracking to guarantee absolute zero-trust process isolation and immutable anti-replay protection across the entire host subsystem.

---

## Rust Sandbox / Dev Environment

This repository includes a reproducible Rust sandbox for development, CI-style
builds, and Step 1 capability-broker testing. It installs Rust/Cargo, native Z3,
SQLite/OpenSSL headers, Python 3, and Clang/LLVM in a Docker image.

```bash
make docker-build
make dev-shell
make docker-smoke
```

For the full workflow, see [docs/rust_sandbox.md](docs/rust_sandbox.md).
If the sandbox MCP gateway port is busy, set `JINN_GUARD_MCP_PORT`, for example:

```bash
JINN_GUARD_MCP_PORT=4860 make smoke
```

## Step 2 Mandatory Mediation Runtime

The repository also includes a locked agent runtime for development validation.
It demonstrates that an agent can be denied direct shell, network, and sensitive
filesystem access while still reaching the Jinn Guard broker over a Unix socket.

```bash
make runtime-smoke
```

The runtime compose profile uses `docker-compose.runtime.yml`:

- `jinnguard-broker` owns the real capabilities and exposes the runtime socket.
- `locked-agent` runs as non-root UID `10001`, with no outbound network,
  read-only workspace, all Linux capabilities dropped, no-new-privileges, shell
  binaries removed, and a seccomp profile for high-risk syscalls.

The Step 2 policy rejects verdict-only dangerous actions with:

```text
SIGNAL: DENY_RUNTIME_POLICY
```

See [docs/step2_mandatory_mediation_sandbox.md](docs/step2_mandatory_mediation_sandbox.md).

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         AI Agent Process                        │
│  (Python SDK / jinnguard_py)                                    │
│    proposal = {agent_id, intent_name, context_vars, ...}        │
│    signed_envelope = HMAC-SHA256(proposal, kernel_keyring_key)  │
└──────────────────────┬──────────────────────────────────────────┘
                       │  UNIX domain socket  /run/jinnguard/jinnguard.sock
                       │  5-byte framed wire protocol (version + length)
                       ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Jinn Guard Daemon (ts_cli)                  │
│                                                                 │
│  1. SO_PEERCRED   → verify kernel PID / UID / GID               │
│  2. HMAC verify   → tamper detection (key from kernel keyring)  │
│  3. G1: Agent lookup  → allowed_intents + max_sequence_quota    │
│  4. Semantic classify → heuristic intent class + risk score     │
│  5. RiskAssessment    → fused_risk, trust_score                 │
│  6. Lineage check     → replay detection + behavioral drift     │
│  7. Policy decision   → risk ceiling + trust floor              │
│  8. G2: Z3 totality audit + per-agent invariant verification    │
│  9. ExecutionBroker   → path / URL / command hard denylist      │
│ 10. Hash-chained audit log  (DENY or ALLOW)                     │
└──────────────────────┬──────────────────────────────────────────┘
                       │
          ┌────────────┴────────────┐
          ▼                         ▼
   SIGNAL: ALLOW              SIGNAL: DENY_*
   (tool executes)            (tool blocked)
```

```
Kernel Layer (eBPF)
  jg_execve.bpf.c    → tracepoint/syscalls/sys_enter_execve
  jg_openat.bpf.c    → tracepoint/syscalls/sys_enter_openat
  jg_connect.bpf.c   → tracepoint/syscalls/sys_enter_connect
  jg_cap_capable.bpf.c → tracepoint/capability/capable
        │
        └─→ RingBuf EVENTS  →  AyaKernelTelemetry (user-space drain thread)
                                        │
                                        └─→ governance loop (telemetry feed)
```

---

## 📦 Components

| Crate / Directory | Purpose |
|---|---|
| `ts_cli/` | Main daemon — UDS listener, enforcement pipeline, audit logger |
| `ts_checker/` | Z3 SMT policy engine — state transition proofs + declarative invariants |
| `jinnguard_py/` | Python SDK for agent integration |
| `bpf/` | eBPF C programs (execve, openat, connect, cap_capable) + Makefile |
| `deploy/` | systemd unit + `install.sh` provisioner |
| `tests/` | Integration test harness |

---

## 🔐 Security Model

| Control | Implementation |
|---|---|
| **Secret management** | HMAC-SHA256 key loaded into Linux kernel keyring (`jinnguard_hmac_key` in `@s`); daemon reads via `SYS_request_key` + `SYS_keyctl`. Fallback: `/etc/jinnguard/secret` (mode `0400`, owner `root`). Env vars never used. |
| **Process identity** | `SO_PEERCRED` on every UDS connection — kernel-verified PID, UID, GID. No client-declared identity is trusted. |
| **Agent identity** | `agent_id` from proposal is matched against `agent_nodes` map in `policy.yaml`. Unknown IDs are hard-denied (`DENY_UNKNOWN_AGENT_ID`). |
| **Intent enforcement** | Per-agent `allowed_intents` allowlist checked before semantic classification (`DENY_INTENT_NOT_ALLOWED`). |
| **Sequence quota** | Per-agent `max_sequence_quota` hard cap on decisions per lineage session (`DENY_QUOTA_EXHAUSTED`). |
| **Replay protection** | Monotonic `sequence_counter` validated per `(pid, start_time)` lineage key (`DENY_REPLAY_ATTACK`). |
| **Behavioral drift** | Statistical drift detector on `fused_risk` delta against lineage baseline (`DENY_BEHAVIORAL_DRIFT`). |
| **Z3 totality proof** | Every request passes through `execute_totality_audit()` — mathematical proof that `fused_risk ≤ upper_safety_boundary`. |
| **Z3 invariants** | Per-agent declarative constraints (`spending_ceiling_usd`, `privilege_escalation_depth`, etc.) verified against daemon-computed runtime state. Callers cannot spoof daemon-observed values. |
| **Audit log** | Hash-chained JSONL log. Each entry includes the SHA-256 of the previous entry — tamper evident. |
| **eBPF telemetry** | Kernel-level visibility into execve, file open, network connect, and capability checks — correlated with governance decisions. |

---

## System Requirements

- Linux kernel 5.16+
- CONFIG_BPF_LSM=y
- Boot parameter: lsm=bpf
- bpftool installed (for vmlinux.h generation)

---

## Known Limitations

### Filesystem path resolution — mount boundaries (was CVE-2026-002, now fixed)

The BPF `inode_create`/`inode_unlink` hooks now resolve the **full absolute
path** of a file operation in the kernel (a bounded `d_parent` walk), closing the
earlier basename-only bypass. Validated live (audit-only) via
`scripts/validate_m2_path_resolution.sh`.

Residual limitation: the inode hooks receive a dentry without a vfsmount, so a
file on a **sub-mount** (e.g. a tmpfs `/tmp`) resolves relative to that mount's
root (`/tmp/x` → `/x`). Root-filesystem paths (`/etc`, `/usr`, `/opt`, `/home`
on a single-root install) — the security-critical cases — resolve to full
absolute paths. Crossing mount boundaries requires path-family LSM hooks or
`bpf_d_path` and is tracked for a future release.

### Interpreter chains (CVE-2026-001, mitigated)

An agent explicitly allowed to run an interpreter can invoke other tools through
it. Jinn Guard denies known interpreters by policy for governed agents (any
agent carrying an executable allowlist); per-binary execve limits remain only as
strong as that allowlist.

---

## 🚀 Quick Start

### Prerequisites

```bash
# Debian/Ubuntu
sudo apt install libz3-dev llvm clang libbpf-dev keyutils

# Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### Install (automated)

```bash
git clone https://github.com/AlphaReasoning/The-Jinn-Guard
cd The-Jinn-Guard
sudo ./deploy/install.sh
```

The installer will:
1. Create the `jinnguard` system user
2. Generate a 256-bit HMAC secret → `/etc/jinnguard/secret`
3. Load the key into the kernel keyring
4. Build and install `/usr/sbin/jinnguard`
5. Enable and start `jinnguard.service`

### Manual key provisioning

```bash
# Load existing secret into kernel keyring
keyctl add user jinnguard_hmac_key "$(cat /etc/jinnguard/secret)" @s

# Verify the key is present
keyctl show @s
```

### Service management

```bash
systemctl status jinnguard
journalctl -u jinnguard -f
```

### Python client example

```python
from jinnguard_py import JinnGuardClient

client = JinnGuardClient(
    socket_path="/run/jinnguard/jinnguard.sock",
    secret_key="<your-hmac-secret>",  # or use keyring lookup
    agent_id="fabric_swarm_production_01",
)

result = client.propose(
    intent_name="read_file",
    sequence_counter=1,
    action_risk_score=20.0,
    proposed_action={"kind": "file_write", "path": "/tmp/out.txt", "contents": "hello"},
    context_vars={"spending_ceiling_usd": 50.0},
)

if result.allowed:
    print("Execution permitted:", result.signal)
else:
    print("Blocked:", result.signal)
```

---

## ⚙️ Configuration — `policy.yaml`

```yaml
upper_safety_boundary: 75.0   # fused_risk must be below this
minimum_trust_score: 20.0     # trust_score must be above this

agent_nodes:
  fabric_swarm_production_01:
    privilege_tier: 1
    allowed_intents:
      - read_file
      - model_inference
      - write_temp
    max_sequence_quota: 500    # max decisions per lineage session (0 = unlimited)
    invariants:
      - "spending_ceiling_usd <= 150.00"
      - "privilege_escalation_depth < 3"
      - "fused_risk <= 74.0"

  admin_agent_00:
    privilege_tier: 3
    allowed_intents: []        # empty = all intents allowed
    max_sequence_quota: 0      # 0 = unlimited
    invariants:
      - "trust_score >= 30.0"
```

### Invariant syntax

Invariants are simple infix expressions resolved by the Z3 real-arithmetic solver:

```
<variable> <op> <literal>
```

| Operator | Meaning |
|---|---|
| `<=`, `>=`, `<`, `>`, `==` | Standard comparison |

**Daemon-authoritative variables** (cannot be spoofed by the caller):

| Variable | Source |
|---|---|
| `fused_risk` | `RiskAssessment::assess()` |
| `trust_score` | `RiskAssessment::assess()` |
| `observed_risk`, `semantic_risk`, `topology_risk` | Assessment sub-components |
| `is_root` | `SO_PEERCRED` UID = 0 → 1.0 |
| `privilege_tier` | Agent node policy config |
| `decisions_seen` | Lineage registry |
| `max_assessed_risk` | Lineage registry |
| `privilege_escalation_depth` | Derived from `is_root × decisions_seen` |

**Caller-supplementable variables** (agent can declare, daemon values take precedence):

| Variable | Example |
|---|---|
| `spending_ceiling_usd` | Tool execution cost declared by the agent |
| Any custom key | Passed in `proposal.context_vars` |

---

## 🗂️ Runtime Paths

| Resource | Path |
|---|---|
| UDS socket | `/run/jinnguard/jinnguard.sock` |
| Audit log | `/var/log/jinnguard/audit.log` |
| Lineage store | `/var/lib/jinnguard/lineage.json` |
| Policy config | `/etc/jinnguard/policy.yaml` |
| HMAC secret | `/etc/jinnguard/secret` (mode `0400`, owner `root`) |
| eBPF object | `/usr/lib/jinnguard/jinnguard_ebpf.o` |

---

## 🔧 CLI Flags

```bash
jinnguard [OPTIONS]

Options:
  --socket-path   <PATH>   UDS socket path  [default: /run/jinnguard/jinnguard.sock]
  --lineage-file  <PATH>   Lineage persistence file  [default: /var/lib/jinnguard/lineage.json]
  --audit-log     <PATH>   Audit log path  [default: /var/log/jinnguard/audit.log]
  --policy-file   <PATH>   Policy YAML  [default: /etc/jinnguard/policy.yaml]
  -h, --help               Print help
```

---

## 🧬 Building eBPF Programs

```bash
# Prerequisites
sudo apt install clang llvm libbpf-dev linux-headers-$(uname -r)

# Build all four programs and merge into jinnguard_ebpf.o
cd bpf && make

# Install to /usr/lib/jinnguard/
sudo make install
```

The merged object is loaded at runtime by the `aya-rs` backend inside the daemon when built with the `kernel_telemetry` feature.

---

## 🧪 Development

```bash
# Run all unit tests (4 Z3 + 12 governance)
cargo test

# Run benchmarks
cargo bench

# Benchmarks cover:
#   z3_state_transition        — risk check hot path at various risk levels
#   z3_policy_invariants       — 2-constraint and 5-constraint invariant solve
#   totality_audit             — per-connection Z3 ceiling proof
#   uds_socket_saturation      — raw UDS framed roundtrip latency
#   uds_socket_saturation      — persistent connection variant

# Check without building
cargo check
```

---

## 📊 Validation status — validated research prototype / controlled-pilot MVP

> **Independent reviewers:** see [`PROFESSOR_VALIDATION.md`](PROFESSOR_VALIDATION.md)
> and run `bash scripts/run_professor_validation.sh` for a one-command, tiered
> validation of everything below.

**Validated on a real Linux 6.12 host:**

| Capability | How it was validated |
|---|---|
| Full automated suite (≈117 tests) | `cargo test --workspace` — Z3 engine, governance pipeline, 13 integration, 12 swarm-attack, anti-lockout + safe-mode invariants |
| Mandatory mediation | Docker locked-agent: 7/7 probes — direct network/`/etc`-write/shell blocked, broker-mediated actions succeed |
| Kernel full-path resolution | eBPF-LSM hooks load + resolve absolute paths live (audit-only) |
| Kernel allow/deny enforcement | `tests/kernel_lsm.rs` allow/deny suite (execve, TCP, UDP, create, unlink), zero fail-open — *run on a spare host* |
| Anti-lockout guarantee | CI-enforced tests: base-system/desktop processes always allowed when armed; safe mode stays audit-only |

This is **not** independently audited or enterprise-GA. It is a strong,
test-backed prototype demonstrating OS-level AI-agent enforcement.

### ✅ Shippable components

| Component | Status |
|---|---|
| UDS IPC transport (framed, version-tagged) | ✅ Production |
| HMAC-SHA256 authentication | ✅ Production |
| Kernel keyring secret management | ✅ Production |
| `SO_PEERCRED` process identity | ✅ Production |
| Z3 totality audit | ✅ Production |
| Z3 per-agent invariant verification (G2) | ✅ Production |
| Per-agent intent allowlist enforcement (G1) | ✅ Production |
| Per-agent sequence quota enforcement (G1) | ✅ Production |
| Replay attack protection | ✅ Production |
| Behavioral drift detection | ✅ Production |
| Hash-chained audit log | ✅ Production |
| ExecutionBroker hard denylist | ✅ Production |
| Lineage persistence | ✅ Production |
| systemd unit + installer | ✅ Production |
| Python SDK (`jinnguard_py`) | ✅ Functional |
| eBPF C sources (4 programs + Makefile) | ✅ Source complete |
| UDS saturation benchmark | ✅ Implemented |

### 🔴 Remaining gaps before 100%

| Gap | Effort |
|---|---|
| eBPF compilation in CI (clang/libbpf in build image) | Medium |
| mTLS for optional RootAI remote semantic service | Medium |
| OpenTelemetry metrics export (Prometheus endpoint) | Medium |
| `CAP_BPF` privilege drop after eBPF program load | Small |
| Structured CLI error codes (machine-parseable) | Small |
