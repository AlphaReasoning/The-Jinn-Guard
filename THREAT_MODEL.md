# Jinn Guard — Threat Model & Security Review

**Status:** v1.0.0-rc1 · validated research prototype / controlled-pilot MVP
**Scope of this document:** the security model, trust boundaries, adversary
assumptions, attack surface, and the threat→mitigation mapping for the system as
it actually ships today. Every mitigation below is tied to a concrete control in
the code and, where possible, to an automated test or a live validation result.

> This is a structured **self-review**, not a third-party audit. It is written to
> be checked: a reviewer can run `scripts/run_professor_validation.sh` and map
> each PASS back to the rows below. Independent audit remains the open item
> (see §9). The historical white-box audit that first surfaced CVE-2026-001 and
> CVE-2026-002 is preserved in [`red-team-report.md`](red-team-report.md); note
> that report describes an aspirational mTLS identity model — the shipped system
> uses HMAC-SHA256 over a local Unix-domain socket, documented accurately here.

---

## 1. System overview and trust boundaries

Jinn Guard mediates the actions of an autonomous AI agent at the operating-system
boundary, treating the agent as **untrusted**. There are two enforcement planes:

1. **User-space governance daemon (`ts_cli`).** An agent (or a broker acting for
   it) connects over a local Unix-domain socket and submits HMAC-signed
   *proposals*. The daemon runs each proposal through a fixed gate chain
   (`main.rs`, STEP 1–16) and returns ALLOW/DENY with an auditable reason.
2. **Kernel eBPF-LSM enforcement.** Five LSM hooks (`bprm_check_security`,
   `socket_connect`, `socket_sendmsg`, `inode_create`, `inode_unlink`) make
   synchronous allow/deny decisions in the kernel, independent of any cooperation
   from the agent process.

### Trust boundaries

| Boundary | Trusted side | Untrusted side |
|---|---|---|
| Unix-domain socket | The daemon + the HMAC secret | The connecting agent/broker |
| `bprm`/socket/inode LSM hooks | Kernel + installed policy maps | Every governed user-space process |
| HMAC secret | Kernel keyring / `--secret-file` (root-owned) | The agent |
| cgroup scope | The operator's session + system services | The governed agent cgroup |

The **operator** (the human running the host) is trusted and is, by explicit
design, never subject to kernel denial (see §6).

---

## 2. Assets and security goals

| Asset | Goal |
|---|---|
| Host integrity (filesystem, processes) | An agent cannot create/delete files or exec binaries outside policy |
| Network egress | An agent cannot reach denied destinations |
| Decision integrity | Every decision is authenticated, replay-proof, and totally-ordered per agent |
| Auditability | Every decision is recorded in a tamper-evident, hash-chained log |
| Operator availability | Enforcement can **never** lock the operator out of their own machine |
| Determinism | Identical inputs yield identical decisions; the adaptive layer only ever tightens |

---

## 3. Adversary model

**In scope — a malicious or compromised agent that can:**
- Open the Unix socket and send arbitrary bytes / malformed frames.
- Replay, reorder, or tamper with previously-seen proposals.
- Claim arbitrary `agent_id`s, including unknown or empty/anonymous identities.
- Attempt intent injection, delegation forgery, and quota-exhaustion races.
- Spawn child processes, attempt network connections, and create/delete files
  directly (bypassing the proposal path entirely) to test the kernel plane.
- Attempt to bypass `execve` allowlists via interpreter chains.
- Attempt filesystem-policy bypass via relative/odd paths.

**Out of scope (explicit assumptions):**
- An adversary who is already **root** on the host, or who can load kernel
  modules / disable LSM, is out of scope — they are above the enforcement plane.
- Physical access and firmware/boot-level attacks.
- Side channels (timing, cache) against the Z3 layer.
- The correctness of the Linux kernel, eBPF verifier, and HMAC primitive itself.
- Supply-chain compromise of the build toolchain.

---

## 4. Attack surface

| Surface | Entry point | Primary control |
|---|---|---|
| IPC framing | 5-byte header + length-prefixed payload (`main.rs` STEP 1–2) | Bounded reads, version tag, explicit length cap |
| Proposal authenticity | `SignedEnvelope` HMAC-SHA256 (STEP 3–4) | Constant-time MAC verify against keyring/secret-file key |
| Identity | `agent_id` from inner JSON + `SO_PEERCRED` peer creds | Unknown/anonymous gates (STEP 7–8) |
| Ordering | Per-`(pid, start_time)` lineage sequence counter (STEP 6) | Monotonic replay gate |
| Authorization | Intent allowlist, runtime policy, quota (STEP 9–11) | Per-agent policy, fail-closed |
| Risk/ceiling | Adaptive penalty + Z3 invariants + hard ceiling (STEP 12–13) | Deterministic, tighten-only |
| Kernel execve | `bprm_check_security` | In-kernel allowlist, cgroup-scoped |
| Kernel network | `socket_connect`, `socket_sendmsg` | In-kernel IP denylist, cgroup-scoped |
| Kernel filesystem | `inode_create`, `inode_unlink` | Full-path resolution + denylist, cgroup-scoped |

---

## 5. Threats → mitigations (with evidence)

Evidence keys: **UT** = unit test, **IT** = integration test, **SW** = swarm-attack
suite, **K** = live kernel validation (Tier 4), **D** = Docker mandatory-mediation
(Tier 2), **AO** = live audit-only kernel (Tier 3).

| # | Threat | Mitigation | Control | Evidence |
|---|--------|-----------|---------|----------|
| T1 | Forged/tampered proposal | HMAC-SHA256 over inner payload; mismatch → DENY before any gate | `main.rs` STEP 3–4 | SW, UT |
| T2 | Replay / reorder of a valid proposal | Monotonic sequence per `(pid,start_time)` lineage key → `DENY_REPLAY_ATTACK` | STEP 6 | SW, IT |
| T3 | Anonymous / empty identity | Empty/unparseable `agent_id` denied | STEP 7 | SW |
| T4 | Unknown agent (not in policy) | No matching agent node → DENY | STEP 8 | SW |
| T5 | Intent injection (action outside declared intents) | Per-agent intent allowlist | STEP 9 | SW, UT |
| T6 | Delegation forgery | Delegation/lineage checks reject forged chains | STEP 5–6, governance | SW |
| T7 | Quota-exhaustion race | Slot reserved under lock before decision | STEP 11 | SW, UT |
| T8 | Invariant violation slips through | Z3 SMT invariants + hard global safety ceiling | STEP 12–13 | UT (Z3), IT |
| T9 | Fail-open via "out-of-scope/immune" fast-path | Fast-paths moved **after** the full gate chain (STEP 11.5) | STEP 11.5 | IT, SW (regression fixed) |
| T10 | Direct host action bypassing the proposal path | Kernel LSM enforces independently of user-space cooperation | 5 LSM hooks | K, D |
| T11 | execve allowlist bypass via interpreters (CVE-2026-001) | Governed agents denied known interpreters → `DENY_INTERPRETER_NOT_ALLOWED` | `interpreter_bypass_denied()` | UT |
| T12 | Filesystem policy bypass via relative paths (CVE-2026-002) | Kernel resolves full absolute path before the denylist check | `jg_read_dentry_path()` | AO, K |
| T13 | Repeat offender keeps probing | Deterministic, bounded, tighten-only risk penalty | `adaptive_risk_penalty()` (M6) | UT |
| T14 | Mandatory mediation bypass | Locked agent: no network, RO fs, all caps dropped, seccomp, socket-only | Docker compose profile | D (7/7 probes) |
| T15 | Audit tampering | Hash-chained audit log | governance audit log | UT |

### CVE log

| CVE | Severity | Status | Resolution |
|---|---|---|---|
| **CVE-2026-002** — filesystem policy bypass via relative paths | Critical | **Fixed** | Kernel-side full-path resolution (`jg_read_dentry_path`, depth-12 dentry walk). Live-verified audit-only (Tier 3) and armed (Tier 4). Residual: sub-mount paths resolve relative to their mount root — root-fs paths (`/etc`,`/usr`,`/opt`) resolve absolutely (§7). |
| **CVE-2026-001** — execve bypass via interpreter chains | High | **Mitigated** | Governed agents with an allowlist are denied known interpreters (`/bin/sh`, `/bin/bash`, `python`, …). Per-binary limits remain only as strong as the allowlist (§7). |

---

## 6. Operator-availability analysis (anti-lockout)

The defining safety property: **enforcement can never lock the operator out.**
This was a real historical failure mode (turning off safe mode froze the
desktop). It is now addressed structurally in three layers:

1. **Safe mode (audit-only).** The kernel programs set an audit-only control bit
   **before** they attach (`ebpf_monitor.rs`); every hook returns `0` (allow)
   regardless of the computed decision. A missing control map → refusal to load
   (fail-safe). Invariant-tested (`safe_mode_invariants`).
2. **cgroup-scoped enforcement.** Each hook calls `bpf_get_current_cgroup_id()`
   and **passes through any task not in the governed cgroup** before doing any
   work — no decision, no telemetry. The scope id is written to the map *before*
   attach, so there is never a host-wide enforcement window. Configured via
   `JINNGUARD_GOVERN_CGROUP`; default (unset) preserves prior global behavior for
   deployments that want it. **This fails safe toward the operator:** a wrong or
   too-narrow scope makes governed probes *ungoverned* (tests report `fail_open`
   and fail loudly) rather than widening to the desktop.
3. **Policy-level guards.** Base-system path prefixes are rejected at policy
   install **and** re-excluded at lookup; the operator's own processes are never
   placed under governance (`operator_safety_invariants`, M1/M3).

**Live evidence.** Tier 4 was run armed on a single-machine laptop (kernel 6.12)
with **no lockout**: 2,500 enforced operations across all five surfaces with
`fail_open=0` and `incorrect_decision=0`, while the operator session remained
fully interactive. A reboot clears all kernel state unconditionally (nothing is
persisted; no enforcing service is auto-enabled), and the validation harness
wraps armed runs in a hard 10-minute watchdog.

---

## 7. Residual risks and known limitations (disclosed)

1. **Not independently audited.** This document is a self-review. Third-party
   audit is the headline open item.
2. **Single-distribution validation.** Validated on Debian/trixie, kernel 6.12.
   Other distros/kernels are untested (BTF/CO-RE should port, but unproven).
3. **Mount-boundary path resolution.** Inode hooks have no vfsmount; a file on a
   sub-mount (e.g. a tmpfs `/tmp`) resolves relative to that mount's root.
   Root-filesystem paths — the security-critical cases — resolve absolutely.
4. **Interpreter chains (CVE-2026-001).** An agent explicitly allowed to run an
   interpreter can drive other tools through it. Mitigated by denying
   interpreters for governed agents; not eliminated.
5. **Root-equivalent adversary is out of scope** by assumption (§3).
6. **HMAC secret distribution.** Security reduces to protecting the shared key
   (kernel keyring / root-owned secret file). Key rotation is not yet automated
   (tracked for productionization).
7. **DNS mediation is heuristic.** `sendmsg`-to-:53 payload inspection is
   best-effort, not a full resolver-level policy.

---

## 8. Determinism and the adaptive layer

The risk/adaptive layer (M6) is constrained to preserve determinism: the
per-agent penalty is **pure, monotonic, bounded (cap 40.0), non-negative, and
tighten-only**. It is applied before the Z3 invariants and the hard ceiling, and
it never loosens a decision, never touches operator/immune/out-of-scope paths,
and never makes an ALLOW out of a DENY. Properties are pinned by
`adaptive_floor_tests`. The system is therefore *adaptive yet deterministic*:
the same observation history always yields the same decision.

---

## 9. Open items before "audited GA"

| Item | Type |
|---|---|
| Independent third-party security audit | External review |
| Multi-distribution / multi-kernel validation matrix | Engineering |
| Automated HMAC key rotation | Engineering |
| mTLS/auth for the optional MCP/remote semantic service | Engineering |
| Full effective-set deprivilege after load | Hardening |
| OpenTelemetry / push-based metrics (a loopback Prometheus `/metrics` endpoint already ships) | Operability |

**Closed post-rc1 (M7 hardening):** eBPF compilation is now gated in CI; startup
failures use structured machine-parseable exit codes; opt-in post-load
capability hardening (`no_new_privs` + bounding-set drop via
`JINNGUARD_HARDEN_CAPS=1`) reduces the daemon's post-compromise capability
without affecting enforcement.

---

## 10. How to reproduce the evidence

```bash
# Tiers 1–2 (no root): full suite + Docker mandatory mediation
bash scripts/run_professor_validation.sh
# Tier 3 (root, audit-only): kernel full-path resolution, blocks nothing
sudo bash scripts/run_professor_validation.sh
# Tier 4 (root, cgroup-scoped): real allow/deny, fail_open=0
sudo bash scripts/run_professor_validation.sh --arm
```

Each tier's PASS maps directly back to the evidence keys in §5. See
[`PROFESSOR_VALIDATION.md`](PROFESSOR_VALIDATION.md) for the per-tier breakdown.
