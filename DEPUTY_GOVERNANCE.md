# Governing the deputy: caller-identity propagation across the orchestrator boundary

> Design / research note for **JG #57**. This is the "complete but hard fix" for
> the confused-deputy class described in
> [`THREAT_MODEL.md` → *Confused deputy via privileged orchestrators*](THREAT_MODEL.md).
> It records the problem precisely, evaluates four approaches honestly, and names
> the **smallest increment that is actually buildable today** on a stock BPF-LSM
> host — plus the part that remains genuine research.

## 1. The problem: designation is not authority

A governed agent does not need a privilege it holds to do damage; it can **borrow
the authority of a more-privileged, ungoverned daemon** over an IPC channel:

```
governed_agent ──connect()──▶ /var/run/docker.sock ──▶ dockerd (root, ungoverned cgroup)
                                                        docker run -v /:/host … 'write to host'
```

Jinn Guard's enforcement floor is scoped to the **agent's** cgroup:
`jg_in_governed_scope()` keys every decision on `bpf_get_current_cgroup_id()` (and
its ancestors). When `dockerd` performs the privileged action it runs **in its own
cgroup**, which the floor — scoped to the agent — never observes. The agent never
left its sandbox; it commanded a deputy that lives outside it.

This is why capability-denial defenses (drop `CAP_SYS_ADMIN`, block `unshare`/
`mount`, disable unprivileged userns — #50–#53) do **not** help: the agent is not
the one exercising privilege. The fix has to act on the **control channel**, the
one place where the governed caller and the ungoverned deputy still touch.

## 2. What is already enforced

| # | Mechanism | What it does | Residual |
|---|---|---|---|
| **#55** | In-kernel AF_UNIX **denylist** (`socket_connect`) | Governed-scope connect to a built-in list of orchestrator/init sockets (docker, containerd, podman, crio, libvirt, system D-Bus, `systemd/private`; `/run` + `/var/run`) is **denied**. | **Exact-pathname match only.** |
| **#56** | AF_UNIX **deny-by-default allowlist** | With `network_policy.unix_default_deny`, only `allowed_unix_sockets` (+ the JG control socket) are reachable; everything else, including abstract sockets, denied. | Opt-in; abstract sockets can't be allow-listed by path. |
| **#58** | **Detection** (`classify_deputy_connect`) | Every governed connect to a known deputy socket emits `[JINNGUARD DEPUTY ALERT]` + `jinnguard_orchestrator_socket_attempts_total{orchestrator,verdict}`, regardless of verdict. An `allow` is the loudest signal. | Detection only; same path-match limit as #55. |

The structural residual in all three: **the defense is keyed on the socket's
*path*, not on the *identity of the process listening on it*.** A deputy reached by
an abstract-namespace socket, a bind-mounted socket at a non-standard path, or a
deputy simply not on the list (a privileged MCP tool server, a CI/build runner, a
setuid helper) is not matched. And even when matched, #55 only stops *this* agent's
connect — it does not govern the daemon.

## 3. Four approaches considered

### A. Deputy-side eBPF/LSM mediation (non-cooperative)
Attach an LSM/eBPF program on the **deputy's** accept/recvmsg path, resolve the
connecting peer's pid via `SO_PEERCRED`, map that pid to its cgroup, and apply the
**governed** policy to the deputy's resulting action when the caller is governed.
- *Closes:* the real hole — attributes the deputy's action back to the governed caller.
- *Cost:* requires a stable hook on each deputy's action path; attribution across a
  daemon that batches/queues work for many clients (containerd, dbus) is fragile;
  the deputy still runs as root, so you are racing its own execution. **Effective in
  principle, brittle and deputy-specific in practice.** Non-cooperative w.r.t.
  *daemon source*, but very cooperative w.r.t. *daemon internals*.

### B. Authenticating broker / proxy (userspace, non-cooperative)
Deny the raw socket to governed agents (already done by #55/#56) and interpose a
Jinn-Guard broker that the agent must go through; the broker authenticates the
caller (peer cgroup via `SO_PEERCRED`) and enforces policy before forwarding to the
real socket.
- *Closes:* gives a real policy decision point with verified caller identity, on
  **stock kernels, no daemon changes**.
- *Cost:* the broker must understand each deputy's wire protocol (Docker REST,
  containerd gRPC, D-Bus, libvirt RPC) to enforce anything finer than connect/deny;
  a protocol-blind broker is just #55 with extra steps. Best where a **single**
  high-value deputy (e.g. the Docker socket) justifies a protocol-aware shim.

### C. Capability tokens / designation (cooperative)
Issue per-agent, unforgeable, scoped tokens; cooperating deputies require the token
and act only within its scope (designation = authority, done right).
- *Closes:* the hole cleanly — **for cooperating deputies.**
- *Cost:* useless against a deputy that does not check the token, which is every
  deputy that exists today. This is the correct **long-term ecosystem** answer
  (a contract MCP servers and runtimes opt into), not a near-term host control.

### D. Kernel-side credential correlation (non-cooperative, research)
Record `(peer pid → governed cgroup)` at connect time in a BPF map, then correlate
the deputy's **subsequent** privileged syscalls back to the originating governed
caller so the floor can attribute/deny them.
- *Closes:* would be the general fix.
- *Cost:* the correlation is the hard part — a root daemon's later syscalls carry
  **its** task context, not the caller's; tying action *N* by dockerd to connection
  *M* from the agent requires per-deputy request/worker modelling. **Genuine research;
  pid-reuse and worker-pool fan-out make a general solution unsound today.**

## 4. Recommended phased path

The boundary between "tractable" and "research" falls exactly at **whether you must
model the deputy's internal execution.** Approaches that decide **at the connect
chokepoint** (where the governed caller's own cgroup is still the current task) are
tractable now; approaches that must attribute the **deputy's** later actions are not.

- **Near-term (buildable now, stock BPF-LSM, no daemon changes):** make the existing
  connect-time defense **identity-based instead of path-based** — see §5. This
  collapses the abstract-namespace / bind-mount / unlisted-deputy residual of
  #55/#56 into a single rule: *a governed agent may not connect to a socket owned by
  an ungoverned, more-privileged process.*
- **Medium-term:** a **protocol-aware broker (B)** for the one or two deputies that
  warrant fine-grained policy (most likely the Docker/containerd socket), gated
  behind the `enterprise` feature.
- **Research frontier:** **deputy action attribution (A/D)** and the **capability-token
  contract (C)** for a cooperating ecosystem. Documented as open; not promised.

## 5. Smallest tractable increment: peer-identity-keyed connect denial

**Goal.** Replace "deny connects whose *destination path* is on a list" with "deny
governed connects whose *destination socket is owned by an ungoverned privileged
process*." This is the same chokepoint the kernel already mediates
(`jg_socket_connect.c`), so it inherits the existing governed-scope gate and
anti-lockout posture.

**Mechanism (at `socket_connect`, governed scope only):**
1. From the target `struct socket`, walk to the **peer/listening** `unix_sock` and
   read the owning task's cgroup id (the kernel already exposes the peer socket on
   the connecting side; this is a read, not a new attach point).
2. Decide on **identity, not name**: deny (or, under detection-only mode, alert) when
   the peer is **outside the governed scope** *and* privileged (e.g. owned by
   `uid 0`). A peer **inside** the governed scope is just normal intra-agent IPC →
   allow. The path denylist (#55) stays as a fast-path / belt-and-suspenders.
3. Keep the userspace mirror (`classify_deputy_connect`) reporting, now keyed on the
   resolved peer identity so alerts fire for abstract / bind-mounted deputy sockets
   too.

**Why it closes the residual.** Abstract-namespace sockets, bind-mounted socket
paths, and unlisted privileged daemons (MCP servers, CI runners) all share the one
property the path list misses: **a listener owned by an ungoverned privileged
process.** Keying on that property matches them all without enumerating paths.

**Anti-lockout invariants (must hold, pinned by `kernel_lsm` tests):**
- The gate fires **only inside the governed cgroup** (`jg_in_governed_scope`); the
  operator's shell/desktop and every ungoverned task pass straight through, exactly
  as today.
- **`systemd` and `dbus-daemon` stay immune from governance.** We deny the *agent's
  connect*; we never govern the daemon — so there is no conflict and no path to
  bricking the host.
- The Jinn Guard control socket and loopback remain reachable under all floors
  (the existing `test_kernel_anti_lockout_governor_reachable_under_all_floors`
  invariant must continue to pass).
- A governed agent connecting to **another governed process** (peer inside scope) is
  never denied by this rule — only escalation *out of* the scope to a privileged
  owner is.

**Validation.** Adds armed `kernel_lsm` cases on the 3-distro matrix (Debian 13
k6.12, Ubuntu 24.04 k6.17, AlmaLinux 9.8 k5.14): (1) governed connect to a deputy
socket bound at a **non-denylisted path** is now denied/alerted via peer identity;
(2) governed connect to an **abstract-namespace** socket owned by a privileged
ungoverned process is caught; (3) intra-scope agent-to-agent unix IPC still
succeeds; (4) the anti-lockout reachability invariant still holds.

> Feasibility caveat to verify on the matrix before committing to it: reading the
> peer socket's owning-task cgroup from inside `security_socket_connect` must be
> confirmed on the **5.14 floor** (oldest supported verifier). If the peer's cgroup
> is not reliably reachable at that hook on 5.14, fall back to denying on **peer
> `uid 0` + outside-scope** alone (still closes the path-evasion residual), and
> record the kernel-version constraint. No claim is made until it is matrix-green.

## 6. What this does *not* solve

- **It does not govern the deputy.** Once a *legitimately* allowed cooperative path
  exists, the daemon still acts with ambient root. Closing the agent's channel is
  containment, not attribution.
- **Action attribution (A/D) remains open research** — tying a root daemon's later
  syscalls back to the originating governed caller is unsound in general today
  (worker-pool fan-out, pid reuse).
- **The capability-token contract (C) needs ecosystem cooperation** that does not
  exist yet.
- **Architectural limit (unchanged):** a per-process/per-cgroup model cannot govern
  an independent root daemon unless that daemon's **control channel is denied to the
  agent** or the **daemon is itself governed**. The tractable defense remains: treat
  any escalation channel to an ungoverned privileged owner as a denied resource for
  governed agents. §5 makes that treatment identity-based instead of name-based.
