# Jinn Guard — Security Architecture & Trust Boundaries

**Status:** validated research prototype / controlled-pilot MVP
**Scope of this document:** *how the system is built* — its components, the trust
boundaries between them, how a request flows, and where each security decision is
made. It is the structural companion to [`THREAT_MODEL.md`](THREAT_MODEL.md),
which owns the adversary model, the threat→mitigation mapping, and the disclosed
residual risks. Where the two overlap, the threat model is authoritative on
*what can go wrong*; this document is authoritative on *how the pieces fit*.

> Every component and boundary below corresponds to code in this repository.
> Nothing here is aspirational; deferred work is called out explicitly and
> cross-referenced to [`ROADMAP.md`](ROADMAP.md) / the threat model's open items.

---

## 1. The core thesis

Jinn Guard governs an **untrusted autonomous agent** at the operating-system
boundary using **two enforcement planes that do not trust each other to be used**:

1. A **cooperative, adaptive plane** in user space — a governance daemon that an
   agent (or a broker for it) *asks* for permission via signed proposals.
2. A **non-cooperative, deterministic plane** in the kernel — eBPF-LSM hooks that
   make synchronous allow/deny decisions on the real syscalls **whether or not the
   agent ever speaks to the daemon**.

The design principle is *safe non-cooperation*: an agent that ignores the
governance protocol entirely and issues raw syscalls is still contained by the
kernel floor. The adaptive plane can only ever **tighten** a decision the kernel
floor would already permit — it never loosens the floor.

```
                         ┌────────────────────────────────────────────┐
                         │              Untrusted agent                 │
                         │   (LLM / autonomous process, in a cgroup)    │
                         └───────────────┬─────────────────┬───────────┘
            cooperative path             │                 │   non-cooperative path
        (signed proposal, opt-in)        │                 │   (raw syscalls, always)
                                         ▼                 ▼
         ┌───────────────────────────────────────┐   ┌──────────────────────────────┐
         │   PLANE 1 — user-space governance      │   │   PLANE 2 — kernel eBPF-LSM   │
         │   daemon (ts_cli)                      │   │   (10 hooks, cgroup-scoped)   │
         │                                        │   │                              │
         │   UDS + HMAC ─▶ gate chain (STEP 1–16) │   │   bprm / socket / inode /    │
         │   intent ▸ risk ▸ Z3 ▸ ceiling ▸ audit │   │   capable / file_open / mount│
         └───────────────────┬────────────────────┘   └───────────────┬──────────────┘
                             │ ALLOW / DENY + reason                  │ -EPERM / allow
                             ▼                                        ▼
                  ┌───────────────────────┐               ┌────────────────────────┐
                  │  tamper-evident audit  │               │  kernel verdict (final │
                  │  hash chain (#61)      │               │  for the syscall)      │
                  └───────────────────────┘               └────────────────────────┘
```

See [`THREAT_MODEL.md` §1](THREAT_MODEL.md) for the adversary's capabilities
against each plane.

---

## 2. Components

### 2.1 Workspace crates

| Crate | Role | Trust posture |
|---|---|---|
| `ts_cli` | The governance daemon **and** the eBPF-LSM loader. Owns the gate chain, lineage/quota state, the audit log, the BPF map programming, and the verdict loop. | Trusted (runs as the operator's privileged service) |
| `ts_checker` | The deterministic policy verifier — evaluates Z3/SMT **invariants** over a decision. Pure, side-effect-free. | Trusted library |
| `ts_wire` | The wire protocol: `SignedEnvelope` framing, HMAC-SHA256 sign/verify, delegation/lineage summaries. | Trusted library; parses untrusted bytes |
| `examples/` | Demos and legacy stubs. **Not** part of the trusted computing base. | Untrusted / illustrative |

### 2.2 `ts_cli` modules (user-space plane)

| Module | Responsibility |
|---|---|
| `main.rs` | The 16-step gate chain (STEP 1–16), CLI/daemon lifecycle, the kernel verdict loop. |
| `governance.rs` | Lineage registry (per-`(pid,start_time)` sequence ordering + quota), semantic scoring (local heuristic plus optional RootAI over mTLS), `RiskAssessment`, the `ExecutionBroker`, and the **tamper-evident `AuditLogger`** (hash chain + erasable PII store, #61). |
| `explainability.rs` | Turns a raw LSM/proposal event into an `ObservationRecord` + intent/risk classification with a human-readable reason. |
| `ebpf_monitor.rs` | Loads the LSM objects, programs the policy maps (allow/deny lists, scope, runtime controls), and runs the kernel→user-space request/verdict loop. |
| `fleet_policy.rs` | Verifies signed, versioned policy bundles from an external fleet control plane (gated behind the `fleet` feature; off by default). |
| `mcp_gateway.rs` | Optional MCP integration surface for agent frameworks. |
| `metrics.rs` | Prometheus `/metrics` (loopback-only) and OTLP/HTTP JSON export (both opt-in). |
| `system_immunity.rs` | The operator/host-immunity allowlist — paths and processes that are *never* subject to denial (anti-lockout). |

### 2.3 Kernel plane — eBPF-LSM objects (`bpf/lsm/`)

Each hook is an independent ELF object with its own maps; only the `requests`
ring buffer is shared. All are **cgroup-scoped** — they no-op for any task outside
the governed cgroup subtree (`jg_in_governed_scope`, `bpf/lsm/jg_common.h`).

| Object | LSM hook | Enforces |
|---|---|---|
| `jg_bprm_check_security.c` | `bprm_check_security` | execve allowlist (default-deny exec in governed scope) |
| `jg_socket_connect.c` | `socket_connect` | IPv4 deny/allow + default-deny egress (#54); AF_UNIX orchestrator denylist (#55) + deny-by-default allowlist (#56) |
| `jg_socket_sendmsg.c` | `socket_sendmsg` | datagram/UDP egress control |
| `jg_inode_create.c` / `jg_inode_unlink.c` | `inode_create` / `inode_unlink` | filesystem write/unlink denial keyed by `(parent dev, ino, basename)` (#52/#60) |
| `jg_capable.c` | `capable` | denies escalation capabilities in a nested user namespace (#53) |
| `jg_file_open.c` | `file_open` | denies `/dev/kvm` open — VM/microVM launch (#51) |
| `jg_sb_mount.c` / `jg_sb_pivotroot.c` / `jg_move_mount.c` | mount family | denies mount-nesting primitives (#50) |
| `bpf/common/governed_floor.h` | — | shared deny helper + the `verdicts` / `runtime_controls` / `governed_scope` maps |

The mount/capability/file_open/inode hooks form an **anti-nesting lattice**: they
deny the specific primitives an agent would use to build a sub-sandbox or VM and
escape the host LSM scope. See [`THREAT_MODEL.md` "Nested execution and sandbox
escape"](THREAT_MODEL.md).

---

## 3. Trust boundaries

| # | Boundary | Trusted side | Untrusted side | Control |
|---|---|---|---|---|
| B1 | Unix-domain socket | Daemon + HMAC secret | Connecting agent/broker | Bounded framed reads, version tag, length cap (`ts_wire`, STEP 1–2) |
| B2 | Proposal authenticity | Current keyring/secret-file key plus optional previous key during bounded grace; optional per-agent key files override the shared key for matching `agent_id` values | Proposal bytes | Constant-time HMAC-SHA256 verify (STEP 3–4); previous key expires at operator-configured Unix epoch; per-agent keys are loaded once at startup |
| B3 | Caller identity | `SO_PEERCRED` peer creds + lineage | Self-declared `agent_id` | Unknown/anonymous gates (STEP 7–8); identity is **observed**, not asserted |
| B4 | LSM hooks | Kernel + installed policy maps | Every governed user-space process | Synchronous in-kernel allow/deny, scoped to the governed cgroup |
| B5 | cgroup scope | Operator session + system services | Governed agent cgroup subtree | Subtree match (`bpf_get_current_ancestor_cgroup_id`); unsheddable (#49) |
| B6 | HMAC / fleet keys | Root-owned key files / keyring | The agent | File-perm + optional capability drop after load |
| B7 | Audit PII | Operator (holds pseudonym salt) | Anyone reading the chain | PII kept out of the chain; erasable store + crypto-shredding (#61) |
| B8 | Open-core boundary | Private `jinn-guard-enterprise` repo | Public repo / adopters | Control-plane server & fleet ops are **not** in this repo |

**The operator is trusted and is, by explicit design, never subject to kernel
denial.** Enforcement is confined to the governed cgroup; every other task —
including the operator's shell and host services — passes through untouched. This
is a structural invariant, regression-tested on real kernels
([`THREAT_MODEL.md` §6](THREAT_MODEL.md); tests `test_kernel_ungoverned_host_is_never_locked_out`,
`test_kernel_anti_lockout_governor_reachable_under_all_floors`).

---

## 4. Data flow

### 4.1 Cooperative path (signed proposal)

```
agent ──framed bytes──▶ UDS ──▶ STEP 1–2  decode + length-cap        (B1)
                                STEP 3–4  HMAC verify (constant-time) (B2)
                                STEP 5–6  parse + replay detection    (B3)
                                STEP 7–8  identity / anonymous gates  (B3)
                                           optional agent_id↔UID binding
                                           lineage sequence ordering
                                STEP 9–11 intent allowlist · policy · quota
                                STEP 12   adaptive risk penalty (tighten-only)
                                STEP 13   Z3 invariants + hard ceiling  (ts_checker)
                                STEP 14–15 broker / decision
                                STEP 16   append to tamper-evident audit log (B7)
                          ──▶ ALLOW / DENY + machine-readable reason
```

Each gate **fails closed**: a malformed frame, a bad MAC, an out-of-order
sequence, an unknown intent, or a Z3 `Unknown` (e.g. solver timeout) all resolve
to **DENY**. The adaptive penalty (STEP 12) is monotonic and bounded — it can
raise a risk score but never lower one, so it cannot turn a DENY into an ALLOW.

### 4.2 Non-cooperative path (raw syscalls)

An agent that never opens the socket still triggers the kernel plane on every
governed `execve` / `connect` / `sendmsg` / `inode_create` / `inode_unlink` /
`capable` / `file_open` / `mount`. The LSM hook consults its policy map and
returns the verdict **before** the syscall proceeds (for `file_open`, before the
device driver's own `open`, so the deny wins regardless of whether the resource
exists). The same event is mirrored to user space over the `requests` ring buffer
for telemetry and audit — but the enforcement decision does **not** depend on
user space being alive.

### 4.3 Confused-deputy detection overlay

When a governed agent connects to an orchestrator/init control socket
(docker/containerd/podman/crio/libvirt/D-Bus/systemd), the kernel denylist denies
it (#55) **and** the user-space verdict loop emits a distinct
`[JINNGUARD DEPUTY ALERT]` event plus a Prometheus counter (#58) — detection that
is independent of the verdict, because an *allowed* deputy connection is the
loudest signal of an uncovered escape path.

---

## 5. Identity, authenticity, and ordering

- **Authenticity (B2):** every proposal is an HMAC-SHA256 `SignedEnvelope` over a
  local Unix-domain socket. The shipped system uses a **symmetric MAC**, not
  mTLS/PKI (the historical [`red-team-report.md`](red-team-report.md) describes an
  aspirational mTLS model — the accurate, shipped design is HMAC-over-UDS).
  Operators can optionally configure a per-agent secret directory; if a key file
  exists for a signed `agent_id`, the shared admission key is no longer accepted
  for that id. Agents without a configured file keep the shared key path.
  Optional RootAI remote scoring uses outbound HTTPS/mTLS only for scorer
  transport and never replaces proposal authentication or enforcement gates.
- **Identity (B3):** the daemon does not trust the self-declared `agent_id`. It
  cross-checks `SO_PEERCRED` peer credentials, optionally requires the signed
  `agent_id` to match that agent's configured `allowed_peer_uids`, and binds
  decisions to a per-`(pid, start_time)` **lineage**, so a restarted/forked
  process cannot inherit another's standing.
- **Ordering (B3):** each lineage carries a monotonic sequence counter; replays
  and reorderings are rejected (STEP 6). Audit-log appends are serialized so the
  hash chain cannot fork under concurrency.

---

## 6. The audit & data-protection plane (#61)

The audit log is an append-only **SHA-256 hash chain** (integrity / accountability
— GDPR Art. 5(1)(f), 5(2), 32). Personal data is deliberately kept **out of the
chain**: each entry commits only to a per-install **subject pseudonym**, an opaque
`pii_ref`, and an `HMAC(per-record salt, PII)` commitment. The personal data
lives in a separate, **erasable** store. Erasing a subject destroys their rows and
per-record salts (**crypto-shredding**): the data becomes unrecoverable while
every chain hash still verifies. This reconciles immutability with the right to
erasure (Art. 17). Full model in [`THREAT_MODEL.md` §12](THREAT_MODEL.md).

---

## 7. Open-core boundary (B8)

The public repository is the **single-node enforcement core**. The multi-node
control plane that issues signed policy bundles, the fleet operations, and the
private deployment tooling live in a separate **`jinn-guard-enterprise`**
repository and are never committed here.

| In the public core | In the private enterprise repo |
|---|---|
| Governance daemon + gate chain | Fleet control-plane **server** |
| All eBPF-LSM enforcement | Multi-node policy distribution / signing service |
| `fleet_policy.rs` **client** (verify a signed bundle), gated behind the `fleet` feature, off by default | Fleet operations, deployment, signing keys |
| Audit log, metrics, MCP gateway | — |

Default public builds are single-node and **never reach the network for policy**.
The `--fleet-policy-url` client hook is the stable integration seam; every failure
path keeps the current policy (fail-safe).

---

## 8. Key management

| Key | Storage | Boundary |
|---|---|---|
| Admission HMAC secret | Kernel keyring or root-owned `--secret-file`; optional root-owned `--previous-secret-file` for bounded rotation grace | B2/B6 |
| Per-agent HMAC secrets | Optional root-owned `--agent-secret-dir`; each regular file name is an `agent_id` and its contents are that agent's signing key | B2/B6 |
| Fleet bundle-signing key (verify side) | Root-owned `--fleet-secret-file` (defaults to admission secret) | B6/B8 |
| Audit pseudonym salt | Per-install, generated once, in the audit DB `audit_meta` | B7 |
| Per-record commitment salts | In the erasable `audit_pii` rows (destroyed on erasure) | B7 |

Optional hardening (`JINNGUARD_HARDEN_CAPS=1`) sets `no_new_privs` and drops
dangerous capabilities from the bounding set **after** the LSM programs are loaded,
without removing anything the daemon needs at runtime.

---

## 9. Failure & fail-closed posture

| Condition | Behavior |
|---|---|
| Malformed frame / bad MAC / replay | DENY (cooperative plane) |
| Z3 returns `Unknown` (e.g. solver timeout) | DENY (treated as a violated invariant) |
| User-space daemon dies | Kernel hooks remain attached and keep enforcing; the verdict loop fails closed on a poll error |
| Policy reload fails (fleet) | Keep the last good policy |
| Audit-log write contends | Serialized by a write guard; indices stay contiguous, the chain stays unforked |
| Operator / out-of-scope task | **Never denied** — structurally out of the governed cgroup |

---

## 10. What this architecture does **not** claim

Consistent with the threat model's honesty bar:

- It is a **structured self-review**, not a third-party audit.
- An adversary already **root** on the host, or able to unload the LSM / load
  kernel modules, is **above** the enforcement plane and out of scope.
- The **confused-deputy via ambient-authority daemons** is mitigated by denying +
  detecting the agent's control-channel access (#55/#56/#58), not by governing the
  deputy itself — the complete fix (caller-identity propagation) is open research
  (#57, [`THREAT_MODEL.md` "Confused deputy"](THREAT_MODEL.md)).
- **Supply-chain verifiability** is largely in place (#46): a committed `deny.toml`
  is gated on every push/PR by `cargo deny check` (advisories, licenses, bans,
  sources); CI publishes a CycloneDX SBOM per build; and a tag-triggered
  [`release.yml`](.github/workflows/release.yml) produces **SLSA v3 provenance** and
  **cosign keyless signatures** per release artifact. The release binary is also
  rebuilt twice from clean git archives and byte-compared before publication (see
  [`RELEASE_INTEGRITY.md`](RELEASE_INTEGRITY.md)).

---

## 11. Where to look next

| For… | See |
|---|---|
| Adversary model, threat→mitigation evidence, residual risks | [`THREAT_MODEL.md`](THREAT_MODEL.md) |
| Residual-risk register and release claim boundary | [`RESIDUAL_RISKS.md`](RESIDUAL_RISKS.md) |
| Reproducing the validation tiers | [`PROFESSOR_VALIDATION.md`](PROFESSOR_VALIDATION.md) |
| Day-2 operations, modes, incident response | [`OPERATOR_RUNBOOK.md`](OPERATOR_RUNBOOK.md) |
| Disclosure policy | [`SECURITY.md`](SECURITY.md) |
| OWASP mapping | [`OWASP-MAPPING.md`](OWASP-MAPPING.md) |
| Historical white-box audit | [`red-team-report.md`](red-team-report.md) |
