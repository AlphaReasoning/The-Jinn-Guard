# 🛡️ Jinn Guard — Kernel-enforced semantic firewall for autonomous AI agents (validated research prototype)

[![CI](https://github.com/AlphaReasoning/The-Jinn-Guard/actions/workflows/ci.yml/badge.svg)](https://github.com/AlphaReasoning/The-Jinn-Guard/actions/workflows/ci.yml)

**Jinn Guard** is an asynchronous, kernel-aware semantic firewall designed to enforce mathematical safety constraints on autonomous AI agents before any tool execution is permitted. It intercepts high-level natural language intents and processes them through a lifetime-anchored **Z3 SMT solver pipeline** — verifying state transitions and risk ceilings against formalized compliance models before granting or denying execution authority.

Operating locally over high-throughput **UNIX domain sockets**, the platform binds user-space proxy validation with low-level **eBPF kernel telemetry** and namespace tracking to enforce zero-trust process isolation and anti-replay protection for governed cgroups.

## ▶️ Watch it run

[![Jinn Guard live demo — kernel-aware semantic firewall blocking AI-agent attacks](https://img.youtube.com/vi/aVIEinAn-Jc/maxresdefault.jpg)](https://youtu.be/aVIEinAn-Jc)

*Automated demo (Rust + eBPF): one legitimate request is allowed; real attacks are blocked live by the daemon.*

> ### ▶️ See it live in 5 minutes
> ```bash
> bash scripts/demo.sh        # or: bash scripts/demo.sh --auto
> ```
> A narrated dashboard that drives the **real daemon**: one legitimate request is
> allowed, seven real attacks are blocked live, the daemon's own metrics are read
> back, and the validated numbers + safety guarantees are walked through — plain
> enough for a non-technical audience. Nothing is mocked. Presenter notes and
> safety FAQ: [`DEMO.md`](DEMO.md).

> ### 🔬 For evaluators — don't trust it, *verify* it
> ```bash
> python3 scripts/validate/validate.py        # attacks, determinism, audit-chain, tamper-proof
> ```
> A reproducible, dependency-free harness that drives the real daemon and lets you
> **independently verify** every claim: re-run for determinism, recompute the
> tamper-evident audit hash-chain yourself, corrupt the log and watch it get
> caught, and bring your own attack. See [`scripts/validate/`](scripts/validate/)
> and [`scripts/validate/CLAIMS.md`](scripts/validate/CLAIMS.md).

---

## 📊 Performance & Security at a Glance (measured)

Every number below comes from running the **real daemon** on a **real machine**
(AMD Ryzen 5 7520U, 8 cores, Linux 6.12), with each request driven through the
**complete decision pipeline** — nothing is faked or stubbed. Measured 2026-06-12.
Reproduce locally:

```bash
cargo bench --bench stress_bench          # speed + throughput
cargo test --release --test swarm_attack  # attack resistance
```

Full detail: [`BENCHMARKS-01.md`](BENCHMARKS-01.md).

### ⚡ How fast is each decision?

One "decision" = a full security check (verify signature → replay/identity/intent/
quota gates → risk + Z3 math ceiling → audit). Across **10,000 requests**:

| Half of requests finish under | 95% finish under | 99% finish under | Slowest |
|:---:|:---:|:---:|:---:|
| **257 µs** (P50) | **366 µs** (P95) | **463 µs** (P99) | 1.9 ms |

> **In plain English:** a complete security decision takes about **a quarter of a
> millisecond** — faster than the blink of an eye (~100 ms) by ~400×.

### 🚀 How much can it handle?

| Load | Throughput | Errors |
|---|---|---|
| 10–500 agents at once | **~6,500 decisions/sec** | **0** |
| Single client | ~3,640 decisions/sec | 0 |
| 5,000 mixed allow/deny | 100% classified correctly | 0 |

> **In plain English:** it keeps up with **thousands of agent actions per second**
> without a single dropped or wrong answer.

### 🛡️ Can it be attacked or tricked?

We ran **12 adversarial tests spanning 10 distinct attack types** against the live
daemon (>1,200 hostile requests). All 12 passed — **0 fail-open** (it never once
wrongly allowed an attack):

| Attack | What it tries | Sent | Blocked |
|---|---|:---:|:---:|
| Replay storm | Re-send a captured valid request | 50 | 49 ✅ (1st allowed, rest blocked) |
| Signature forgery | Tampered/forged signatures | 100 | 100 ✅ |
| Intent injection | Call a forbidden action (`rm_all`) | 200 | 200 ✅ |
| Quota exhaustion | Spam past the allowed limit | many | capped at exactly 5 ✅ |
| Risk-ceiling breach | Push a too-risky action past the math limit | 50 | 50 ✅ |
| Anonymous flood | Act with no identity | 200 | 200 ✅ |
| Unknown agent | Impersonate an unregistered agent | 100 | 100 ✅ |
| Bad protocol version | Malformed/old protocol | 50 | 50 ✅ |
| Forged delegation | Fake a delegation token | 20 | 20 ✅ |
| Path traversal (MCP) | Escape allowed paths | 20 | 20 ✅ |
| **All 8 at once** (mixed) | Everything concurrently | 400 | 349 blocked + 50 real requests still correctly allowed ✅ |

> **In plain English:** under a coordinated attack, it blocked every hostile
> request, never failed open, stayed up, and *still* let a legitimate request
> through correctly — in under a millisecond.

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

> **A note on languages.** The probes in `bpf/` are C — small, separately-compiled
> eBPF programs loaded into the kernel. The governance core (the daemon, the Z3
> verification pipeline, the policy engine, and the CLI) is **Rust**, under `ts_cli/`.
> `bpf/**` is marked `linguist-vendored`, so GitHub's language bar reflects the Rust
> core rather than the volume of low-level kernel C.

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

## 🏢 Fleet & Enterprise

This repository is the **open-core, single-node** Jinn Guard: one host, local
`policy.yaml`, governed by the kernel. It is fully functional standalone.

Running Jinn Guard across **many hosts under one signed policy** — a control
plane, central policy distribution with HMAC-signed bundles + rollback
protection, hot-reload, and fleet dashboards — is the **enterprise** layer. The
client side ships here as a stable integration hook compiled only with
`--features enterprise` (off by default); the control-plane **server** and fleet
tooling are distributed separately.

Interested in fleet deployment or a pilot? Open an issue or reach out via the
repo — happy to talk.

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
| **Audit log** | Hash-chained JSONL log (each entry includes the SHA-256 of the previous — tamper evident), and **erasure-safe**: personal data is kept out of the chain and crypto-shredded on a GDPR Art. 17 request, with the chain still verifying. See [`THREAT_MODEL.md` §12](THREAT_MODEL.md). |
| **eBPF telemetry** | Kernel-level visibility into execve, file open, network connect, and capability checks — correlated with governance decisions. |

> **Architecture & trust boundaries:** [`SECURITY_ARCHITECTURE.md`](SECURITY_ARCHITECTURE.md)
> (components, data flow, the two enforcement planes, the open-core boundary).
> **Adversary model & threat→mitigation evidence:** [`THREAT_MODEL.md`](THREAT_MODEL.md).

---

## System Requirements

- Linux kernel 5.16+
- CONFIG_BPF_LSM=y
- `bpf` present in the active LSM list (`cat /sys/kernel/security/lsm`)
  - **Debian** cloud kernels often have it pre-armed.
  - **Ubuntu** does not — append `bpf` to the existing list via the `lsm=` boot
    parameter, then `update-grub` and reboot. For example, in
    `/etc/default/grub`:
    ```
    GRUB_CMDLINE_LINUX="lsm=lockdown,capability,landlock,yama,apparmor,ima,evm,bpf"
    ```
    (List the modules already in `/sys/kernel/security/lsm` plus `bpf`; an
    explicit `lsm=` replaces the kernel default, so include the full set.)
- bpftool installed for `vmlinux.h` generation
  (Debian: `bpftool`; Ubuntu: `linux-tools-generic`)

Validated on three distributions / three kernel generations: **Debian 13 / kernel
6.12** ([`BENCHMARKS-01.md`](BENCHMARKS-01.md), [`BENCHMARKS-02.md`](BENCHMARKS-02.md)),
**Ubuntu 24.04 / kernel 6.17** ([`BENCHMARKS-03.md`](BENCHMARKS-03.md)), and
**AlmaLinux 9 / kernel 5.14 under SELinux Enforcing** ([`BENCHMARKS-04.md`](BENCHMARKS-04.md)).

---

## Known Limitations

> **Advisory registry:** the canonical list of `JG-ADV-*` IDs, status, and fix commits lives in [`SECURITY/ADVISORIES.md`](SECURITY/ADVISORIES.md).
>
> **Note on identifiers:** `JG-ADV-*` are internal, self-identified advisory IDs, not CVE records issued by a CNA.

### Filesystem path resolution — mount boundaries (was JG-ADV-2026-002, now fixed)

The BPF `inode_create`/`inode_unlink` hooks now resolve the **full absolute
path** of a file operation in the kernel (a bounded `d_parent` walk), closing the
earlier basename-only bypass. Validated live (audit-only) via
`scripts/validate_m2_path_resolution.sh`.

Residual limitation (telemetry only, since JG #52): the inode hooks receive a
dentry without a vfsmount, so the **reconstructed path string** for a file on a
**sub-mount** (e.g. a tmpfs `/tmp`) is relative to that mount's root (`/tmp/x` →
`/x`). This affects the logged/audited path, **not** the enforcement decision —
denied directories are matched by their `(s_dev, i_ino)` identity, which a
mount/bind/`pivot_root` remap cannot fool (see THREAT_MODEL §7.1). Root-filesystem
paths (`/etc`, `/usr`, `/opt`, `/home` on a single-root install) also resolve to
full absolute strings. Full cross-mount path *strings* require path-family LSM
hooks or `bpf_d_path` and are tracked for a future release.

### Interpreter chains (JG-ADV-2026-001, mitigated)

An agent explicitly allowed to run an interpreter can invoke other tools through
it. Jinn Guard denies known interpreters by policy for governed agents (any
agent carrying an executable allowlist); per-binary execve limits remain only as
strong as that allowlist.

---

## 🎓 Teaching lab — learn the governance model

[`lab/`](lab/README.md) is a self-contained, dependency-free lab that teaches the
Jinn Guard model — semantic intent → policy → decision → audit — **without** the
kernel/eBPF layer. Students build a mini allow/deny/canary/human-review checker
(`python3 lab/checker_starter.py`), then find and fix a planted audit-logging
flaw. It is explicit about which verdicts the real daemon enforces today
(`ALLOW`/`DENY`) versus which are taught as concepts (`CANARY_TRIGGERED`,
`HUMAN_REVIEW`); the design path to close that gap is in
[`docs/agent_governance_extensions.md`](docs/agent_governance_extensions.md).

## 🚀 Quick Start

### Prerequisites

```bash
# Debian/Ubuntu
sudo apt install libz3-dev libssl-dev pkg-config llvm clang libbpf-dev keyutils

# Ubuntu only: bpftool ships inside linux-tools (no standalone package)
sudo apt install linux-tools-generic   # provides bpftool for vmlinux.h generation

# Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

> **Ubuntu note.** `libssl-dev` + `pkg-config` are required (the `openssl-sys`
> dependency). And unlike Debian's cloud kernels, Ubuntu does **not** arm `bpf`
> in its default LSM list — see [System Requirements](#system-requirements) to
> enable it before running kernel enforcement. Validated end-to-end on Ubuntu
> 24.04 / kernel 6.17 — see [`BENCHMARKS-03.md`](BENCHMARKS-03.md).

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
# Prerequisites (Debian)
sudo apt install clang llvm libbpf-dev linux-headers-$(uname -r) bpftool
# On Ubuntu, bpftool comes from linux-tools-generic instead of a `bpftool` package:
# sudo apt install clang llvm libbpf-dev linux-headers-$(uname -r) linux-tools-generic

# Build all four programs and merge into jinnguard_ebpf.o
cd bpf && make

# Install to /usr/lib/jinnguard/
sudo make install
```

The merged object is loaded at runtime by the `aya-rs` backend inside the daemon when built with the `kernel_telemetry` feature.

---

## 🧪 Development

```bash
# Run the full suite (122 tests: 4 Z3 + 93 unit + 13 integration + 12 swarm-attack)
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

> **Looking for the headline numbers?** See
> [📊 Performance & Security at a Glance](#-performance--security-at-a-glance-measured)
> above, or [`BENCHMARKS-01.md`](BENCHMARKS-01.md) for full latency,
> throughput, and attack-suite detail.
>
> **Independent reviewers:** see [`PROFESSOR_VALIDATION.md`](PROFESSOR_VALIDATION.md)
> and run `bash scripts/run_professor_validation.sh` for a one-command, tiered
> validation of everything below.

**Validated on three real hosts — Debian 13 / kernel 6.12, Ubuntu 24.04 / kernel 6.17, and AlmaLinux 9 / kernel 5.14 (SELinux Enforcing):**

| Capability | How it was validated |
|---|---|
| Full automated suite (122 tests) | `cargo test --workspace` — 4 Z3 + 93 unit + 13 integration + 12 swarm-attack, plus anti-lockout + safe-mode invariants |
| Mandatory mediation | Docker locked-agent: 7/7 probes — direct network/`/etc`-write/shell blocked, broker-mediated actions succeed |
| Kernel full-path resolution | eBPF-LSM hooks load + resolve absolute paths live (audit-only) |
| Kernel allow/deny enforcement | `tests/kernel_lsm.rs` armed on a real 6.12 host: 2,500 enforced ops across execve/TCP/UDP/create/unlink, **0 fail-open, 0 incorrect decisions** (P50 8–473µs, P99 20–1038µs by surface); enforcement is **cgroup-scoped** so it runs safely without a spare machine. **Re-validated on Ubuntu 24.04 / kernel 6.17** ([`BENCHMARKS-03.md`](BENCHMARKS-03.md)) **and AlmaLinux 9 / kernel 5.14 under SELinux Enforcing** (2,750 ops, 0 fail-open / 0 incorrect; [`BENCHMARKS-04.md`](BENCHMARKS-04.md)) |
| Anti-lockout guarantee | CI-enforced invariant tests **plus** in-kernel cgroup scoping (`bpf_get_current_cgroup_id`): only the governed cgroup is subject to allow/deny, every other task passes through; safe mode stays audit-only |

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

### ✅ Recently closed (post-rc1 hardening)

| Item | Status |
|---|---|
| eBPF compilation gated in CI (compiles all 10 LSM objects, fails the build on a BPF regression) | ✅ Done |
| Structured, machine-parseable CLI exit codes for startup failures (`code=`/`kind=`) | ✅ Done |
| Opt-in capability hardening after BPF load — `no_new_privs` + bounding-set drop (`JINNGUARD_HARDEN_CAPS=1`) | ✅ Done |
| Prometheus `/metrics` + `/healthz` endpoint (opt-in `JINNGUARD_METRICS_PORT`, loopback) | ✅ Done |
| Operator runbook ([`OPERATOR_RUNBOOK.md`](OPERATOR_RUNBOOK.md)): install, monitor, upgrade/rollback, incident response | ✅ Done |

### 🔴 Remaining gaps before 100%

| Gap | Effort |
|---|---|
| mTLS for optional RootAI remote semantic service | Medium |
| OpenTelemetry export (the Prometheus endpoint exists; OTel/push not yet) | Medium |
| Multi-distribution / multi-kernel validation matrix (Debian 13/6.12 + Ubuntu 24.04/6.17 + AlmaLinux 9/5.14 done; broaden coverage over time) | Medium |
| Full effective-set deprivilege after load (beyond the opt-in bounding-set hardening) | Medium |
| Automated HMAC key rotation | Medium |
