# Internal red-team — findings log (#59)

Structured self-review of the Jinn Guard codebase: an adversary walking the actual
attack surface looking for vulnerabilities, fixing each as it is confirmed. This is
the capstone's running log — **not** a third-party audit (that remains an open item
in [`THREAT_MODEL.md`](THREAT_MODEL.md)). Findings are id'd `JG-RT-NNN`.

Severity uses reachability × impact: **HIGH** = remotely reachable, unauthenticated,
high impact; **MED** = needs authentication / local access, or is defense-in-depth
against a partially-mitigated vector; **LOW** = hardening with no known live exploit.

## Batch 1 — externally reachable parsers & the governance front door

### JG-RT-001 — Unbounded body allocation in the MCP gateway (HIGH, fixed)
`mcp_gateway::read_http_request` allocated `vec![0u8; content_length]` directly from
the client's `Content-Length` header with **no upper bound**. The gateway binds
`0.0.0.0:4750` and is unauthenticated unless mTLS is configured (off by default), so
any reachable client sending `Content-Length: 4000000000` forced an immediate ~4 GB
allocation → out-of-memory crash of the governance daemon. The UDS wire protocol
already bounded this (`ts_wire::MAX_PAYLOAD_LEN`); the gateway did not.
- **Fix:** added `MAX_MCP_BODY_BYTES` (4 MiB) and reject an over-limit
  `Content-Length` *before* allocating. Tests:
  `rejects_oversized_content_length_before_allocating`,
  `parses_request_within_body_limit`.

### JG-RT-002 — Unbounded replay cache growth (MED, fixed)
The replay defense stored every accepted `(agent, sequence_counter)` in a
`HashSet` that was never bounded. Because entries are only added *after* HMAC
verification, growth requires the shared secret — but a single authenticated
(compromised or buggy) client, or simply long uptime, grows daemon memory without
bound → memory-exhaustion DoS of the enforcement point.
- **Fix:** replaced the raw set with `ReplayGuard`, a bounded FIFO replay cache
  (`MAX_REPLAY_ENTRIES = 2^20`). At capacity the oldest nonce is evicted; the
  effective replay window stays at the last ~1M accepted proposals, far beyond any
  in-flight reuse, while memory is capped (~tens of MB). The bounded-window
  trade-off is explicit and tested. Tests: `replay_guard_tests::*`.

### JG-RT-003 — CRLF / header injection into the upstream request (MED, fixed)
`forward_to_upstream` interpolated client-derived `method`, `path`, and `Host`
into the upstream HTTP request line and headers. Inbound `\n`-based line splitting
blocked full CRLF in practice, but a lone `\r` — or any future change to the inbound
parser — would let a crafted value inject a header or smuggle a second request into
the upstream connection.
- **Fix:** refuse to forward when `method`/`path`/`Host` contain any control
  character (`\r`, `\n`, NUL), before connecting upstream. The forwarder already
  recomputes `Content-Length` from the actual body (no client-driven CL/TE desync).
  Test: `refuses_to_forward_crlf_in_request_line`.

## Surfaces reviewed and found sound (batch 1)

- **`ts_wire` (frame + envelope decode + HMAC verify).** Length-bounded before
  allocation, panic-free, constant-time HMAC (`constant_time_eq`), signature checked
  before any proposal parsing. Backed by the #41 fuzz harness + mutation tests. No
  finding.
- **Audit log persistence.** Chain entries are written via `serde_json` (escapes
  user data — no JSONL injection); PII is stored via `rusqlite` `params!`
  (parameterized — no SQL injection). No finding.
- **HMAC secret loading.** `load_secret_from_file` falls back to the keyring/env and
  `fatal`-exits if no secret is available — it never silently substitutes an empty or
  default key, so signatures are not forgeable on a missing-file condition. No finding.
- **MCP gateway mTLS (JG #11).** Client cert required + verified; handshake failure
  drops the connection fail-closed. No finding.

## Batch 2 — kernel floor, policy proof, fleet, capability hardening

### JG-RT-004 — Invariant over a missing variable fails open (LOW, documented)
`ts_checker::verify_policy_invariants` skips (treats as vacuously satisfied) any
invariant whose variable is absent from `context_vars`. The daemon force-populates
every risk/telemetry variable it owns, so those cannot be suppressed; but an
invariant authored over a *caller-supplied custom* variable can be bypassed by
omitting it. Related: very large caller-supplied values saturate in the `as i32`
scaling. This is a **defense-in-depth** layer (the intent allowlist + kernel exec
enforcement are the primary gates; cf. THREAT_MODEL §8), and the skip is a
deliberate, test-pinned design choice (missing telemetry must not cause spurious
denials).
- **Action:** documented in-code at the skip site with the guidance to author
  security-relevant invariants only over the daemon-guaranteed variables (whose
  presence and bounded range are not attacker-controlled). Semantics intentionally
  **not** flipped to fail-closed — that would deny legitimate optional-telemetry
  policies and is the project owner's call, not a unilateral red-team change.

### Surfaces reviewed and found sound (batch 2)

- **Fleet bundle verification (`fleet_policy.rs`).** The signed canonical binds the
  policy via `sha256(policy_yaml)`, so any tamper changes the recomputed hash and
  fails verification; rollback (`version < min_version`) is checked *before*
  signature and the floor ratchets on apply; HMAC compared constant-time. No finding.
- **Z3 / policy proof (`ts_checker`).** A per-`check()` 250 ms solver timeout returns
  `SatResult::Unknown`, which every call site maps to **DENY** — the SMT layer fails
  *closed* on a pathological/timed-out proof. No finding (beyond JG-RT-004 above).
- **BPF LSM `socket_connect` hook (`bpf/lsm/`).** Every `bpf_map_lookup_elem` is
  null-checked before deref; address reads are length-bounded (`bpf_probe_read_*`
  with `sizeof`); IPv6 under default-deny fails closed (no un-allowlisted bypass).
  eBPF memory safety is additionally enforced by the **kernel verifier at load**
  (gated by the `build-ebpf` CI job + exercised by the real-kernel matrix), so OOB /
  null-deref / unbounded-loop bugs cannot load. No finding.
- **Capability hardening (`main.rs`).** `apply()` runs **after** BPF `load()` +
  `attach_all()` (dropping caps earlier would break enforcement); it drops only from
  the *bounding* set (effective caps stay intact, so map writes keep working) and
  sets `no_new_privs`; a test guards the drop list against required caps. No finding.

## Batch 3 — explainability emitter, capability deprivilege

### JG-RT-005 — Log injection into the human console explanation (LOW, fixed)
`DecisionExplanation::to_console_output` interpolated attacker-controlled fields
(`agent_id`, resource path, action, reasons) raw via `{}`, so an embedded newline
could forge a fake `[JINN-GUARD] ALLOW …` line in the human console log. The
structured `to_structured_log` channel was already injection-safe (serde-escaped).
- **Fix:** `sanitize_log_field` replaces control characters with `U+FFFD` in those
  fields before the human output. Test: `console_output_is_not_log_injectable`.

### Full effective-set deprivilege (hardening, implemented + matrix-validated)
The capability hardening (#25) previously dropped only the *bounding* set (prevents
re-acquisition, not use). `JINNGUARD_HARDEN_CAPS=1` now also reduces the live
(effective + permitted) set to `RETAINED_CAPS` via `capset(2)` after BPF attach, so a
post-compromise daemon cannot wield a dangerous capability. The real-kernel matrix
runs its armed enforcement tests with hardening enabled (5.14/6.12/6.17), so a drop
that broke BPF map ops / `/proc` enrichment / enforcement fails CI. Unit test
`effective_retained_mask_keeps_required_drops_dangerous` pins the mask invariants.

## Remaining surfaces (future batches)

- Per-request secret re-read inside the connection loop (a missing-file mid-connection
  triggers `fatal`/exit — fail-closed, but a privileged local actor can crash the
  daemon; low severity, fix deferred to a batch that reworks secret caching).
- Integration-level flows (multi-step lineage, quota accounting).
