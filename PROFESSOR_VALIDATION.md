# Jinn Guard — Reviewer Validation Guide

**Prepared for independent review.** This document lets a reviewer verify Jinn
Guard's claims on their own Linux machine in one command. Every claim below maps
to an automated check you can run and inspect.

---

## 1. What Jinn Guard is (and what it is not)

**Jinn Guard is a kernel-anchored governance firewall for autonomous AI agents.**
It treats an AI agent as an untrusted process and mediates its actions —
process execution, network access, filesystem writes, and tool calls — at the
operating-system boundary, *outside* the model. Decisions combine a userspace
policy engine (per-agent identity, HMAC-authenticated proposals, replay
protection, quotas, a Z3 SMT invariant layer, and a hash-chained audit log) with
Linux **eBPF-LSM** kernel hooks that can allow, constrain, or deny an action.

**Honest scope.** This is a *validated research prototype / controlled-pilot
MVP*, not an independently-audited, enterprise-GA product. It demonstrates the
thesis that **AI-agent safety is an operating-system enforcement problem, not
only a model-alignment problem.** It has not undergone third-party security
audit or multi-distribution hardening.

---

## 2. One-command validation

From the extracted project directory:

```bash
# Safe tiers (no root, nothing is blocked):
bash scripts/run_professor_validation.sh

# Add the kernel audit-only tier (root, still blocks nothing):
sudo bash scripts/run_professor_validation.sh
```

The script detects your machine's capabilities and runs the matching tiers,
then prints a PASS/SKIP/FAIL summary. Skipped tiers tell you what they need.

| Tier | What it proves | Requirements | Blocks anything? |
|------|----------------|--------------|------------------|
| **1. Build + tests** | The full automated suite passes (≈117 tests: Z3 engine, governance pipeline, 13 integration, 12 swarm-attack). | Rust (`cargo`) | No |
| **2. Mandatory mediation** | A maximally-locked agent container (no network, read-only FS, all capabilities dropped, seccomp, socket-only) **cannot** act directly; only broker-mediated actions through Jinn Guard succeed. | Docker | No (containers) |
| **3. Kernel path resolution** | The eBPF-LSM hooks load and resolve **full file paths** in the kernel (the CVE-2026-002 fix), in **audit-only** mode. | root + BPF-LSM + clang | **No** (audit-only) |
| **4. Kernel enforcement** | Real allow/deny across execve, TCP, UDP, file create, and file unlink. | root + `--arm` | **Yes** — see below |

---

## 3. Tier 4 — arming real enforcement (spare machine only)

Tier 4 is **off by default** and arms genuine kernel denial. While it runs,
localhost networking and some process spawning are blocked. Run it **only on a
disposable/spare machine** — a reboot fully clears all kernel state.

```bash
sudo bash scripts/run_professor_validation.sh --arm
```

It builds and installs the LSM objects, builds the enterprise daemon, and runs
the project's own kernel allow/deny suite (`tests/kernel_lsm.rs`) under a hard
10-minute watchdog that guarantees enforcement is removed even if a test hangs.
Expected output includes per-surface lines like:

```
[KERNEL_LSM_EXECVE] operations=500 expected_allow=250 expected_deny=250 success=250 deny=250 fail_open=0 ...
[KERNEL_LSM_TCP_CONNECT] ... fail_open=0 timeout=0 incorrect_decision=0 ...
```

`fail_open=0` and `incorrect_decision=0` are the assertions that matter: every
denied operation was actually denied, and every allowed operation succeeded.

---

## 4. Requirements summary

- **Tier 1 (always):** Linux + Rust toolchain (`rustup`). ~5 min first build.
- **Tier 2:** Docker Engine (`apt install docker.io docker-compose`).
- **Tiers 3–4:** Linux **5.16+** with BPF-LSM enabled (boot parameter
  `lsm=...,bpf`; verify with `cat /sys/kernel/security/lsm | tr ',' '\n' | grep bpf`),
  plus `clang` and `bpftool` (`apt install clang bpftool libbpf-dev`).

---

## 5. What each result means

- **Tier 1 PASS** → the governance logic, attack simulations (replay, HMAC
  forgery, unknown/anonymous agents, intent injection, delegation forgery,
  quota races), and the anti-lockout safety invariants all hold.
- **Tier 2 PASS** → mandatory mediation is real: the agent is structurally
  unable to bypass Jinn Guard.
- **Tier 3 PASS** → the kernel layer loads and sees the true full path of every
  file operation (closing the path-prefix bypass), observed live without
  blocking anything.
- **Tier 4 PASS** → the kernel actually enforces allow/deny decisions with zero
  fail-open.

---

## 6. Known limitations (disclosed)

- **Mount boundaries (filesystem hooks).** The inode hooks resolve paths within
  a filesystem; a file on a sub-mount (e.g. a tmpfs `/tmp`) resolves relative to
  that mount's root. Root-filesystem paths (`/etc`, `/usr`, `/opt`) — the
  security-critical cases — resolve to full absolute paths.
- **Interpreter chains.** An agent explicitly allowed to run an interpreter can
  invoke other tools through it; Jinn Guard denies interpreters by policy for
  governed agents (CVE-2026-001 mitigation), but per-binary execve limits are
  only as strong as the allowlist.
- **Not independently audited; single-distribution validated (Debian).**

See `README.md` and `red-team-report.md` for the full security model and CVE log.
