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

## Remaining surfaces (subsequent batches)

- BPF LSM hooks (`bpf/lsm/*.c`) — map bounds, helper return checks, verifier-floor
  behaviour on 5.14.
- Policy/Z3 path — pathological policy inputs, the SMT timeout/`Unknown`→DENY path.
- Fleet client (`fleet_policy.rs`) — bundle signature/rollback handling.
- Capability hardening (`main.rs`) — the bounding-set drop and `no_new_privs` ordering.
- Per-request secret re-read inside the connection loop (a missing-file mid-connection
  triggers `fatal`/exit — fail-closed, but a privileged local actor can crash the
  daemon; noted, low severity, fix deferred to a batch that reworks secret caching).
