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

## Batch 4 — admission-secret lifetime

### JG-RT-006 — Per-frame secret reload enables local daemon crash (LOW, fixed)
The UDS verdict loop loaded the HMAC secret inside `handle_client_connection` for
every framed proposal. Startup correctly failed closed when no secret was available,
but after a successful start a privileged local actor who removed or temporarily hid
the backing `--secret-file` could make the next frame trigger `fatal` and terminate
the daemon. That is not a signature-bypass or fail-open issue — verification still
requires the correct key — but it is an avoidable local availability failure.
- **Fix:** load the admission secret once at startup and pass the cached
  `Arc<Vec<u8>>` into UDS connection tasks, matching the MCP gateway's existing
  behavior. Secret rotation remains a supervised restart operation (as documented
  in the operator runbook). Integration test:
  `test_cached_secret_survives_mid_connection_secret_file_removal`.

## Batch 5 — lineage / quota integration flow

### JG-RT-007 — UDS lineage ordering and persistence gaps (MED, fixed)
The primary UDS verdict path had three related lineage/accounting gaps. First, it
used `ReplayGuard` to reject exact duplicate `(agent, sequence_counter)` pairs but
never called `AgentLineage::validate_sequence`, so an authenticated client could send
`seq=100` and then a different signed proposal with `seq=99`; the second proposal was
not an exact replay and could pass policy. Second, UDS lineage updates were in-memory
only: unlike the MCP gateway path, the daemon never called `LineageRegistry::save()`,
so restart lost `last_sequence` and quota history. Third, the post-gate ALLOW
fast-paths (`system_process_immunity`, `outside_enforcement_scope`) could reserve a
quota slot but then `continue` without updating the lineage's `last_sequence` /
risk state.
- **Fix:** reserve monotonic sequence state under the lineage lock after identity
  is known, persist UDS lineage updates via the shared helper, and route the two
  post-gate ALLOW fast-paths through that helper. Integration tests:
  `test_out_of_order_sequence_is_denied_by_lineage`,
  `test_outside_scope_fast_path_persists_lineage_state`.

## Batch 6 — MCP gateway remote abuse paths

### JG-RT-008 — MCP clients could self-attest into system-process immunity (HIGH, fixed)
The MCP gateway ran `system_immunity::mcp_caller_is_immune` before the normal
protected-resource / policy path. That helper trusted JSON-RPC `method` and
client-supplied params such as `caller`, `process_name`, and `command`; over TCP
there is no `SO_PEERCRED`, so a remote client could claim an immune process like
`bash`, `systemd`, or `cargo` and receive the immunity forwarding path.
- **Fix:** MCP system-process immunity no longer trusts any client-declared method
  or params. The Unix socket path keeps kernel-backed peer-credential immunity; the
  TCP gateway must pass through the normal governance gates unless future trusted
  transport metadata is added. Test:
  `mcp_immunity_does_not_trust_client_declared_process_fields`.

### JG-RT-009 — MCP slowloris / unbounded upstream response DoS (MED, fixed)
The gateway bounded inbound `Content-Length`, but connection handlers had no request
read deadline and `forward_to_upstream` used `read_to_end` with no maximum response
size. A slow client could hold handler tasks open cheaply, and a compromised or
misconfigured upstream MCP server could drive unbounded daemon memory growth on an
allowed request.
- **Fix:** added a 5s inbound request read timeout, a 5s upstream connect timeout,
  a 10s upstream response timeout, and an 8 MiB upstream response cap. Test:
  `upstream_response_read_is_bounded`.

## Batch 7 — UDS admission availability

### JG-RT-010 — UDS partial-frame slowloris can pin connection tasks (LOW, fixed)
The Unix-domain-socket verdict loop bounded frame sizes and verified HMAC before
policy parsing, but `read_exact` on the 5-byte header and body had no deadline. A
local actor with socket access could open many connections, send a partial header or
partial body, and hold Tokio tasks/file descriptors indefinitely without completing
admission.
- **Fix:** added a 5s read deadline around each UDS header/body read. Test:
  `uds_frame_read_times_out_on_partial_header`.

## Batch 8 — policy refresh resilience

### JG-RT-011 — Remote policy refresh can hang indefinitely (MED, fixed)
The standalone signed-bundle fetch helper had a timeout, but the daemon's long-running
raw policy-server loop and signed fleet-policy loop built async `reqwest` clients
without request timeouts. A hung or malicious endpoint could stall its refresh task
forever, leaving the daemon pinned to stale policy until restart. Existing signature
and rollback checks still prevented tamper/fail-open, but availability of policy
updates was attacker-controlled by the endpoint.
- **Fix:** both async refresh clients now use a bounded 10s request timeout. The
  optional raw policy-client build failure logs and leaves the daemon running; the
  signed fleet loop keeps its existing fail-safe behavior of preserving the active
  policy on fetch errors.

## Batch 9 — BPF/userspace verdict mirror consistency

### JG-RT-012 — AF_UNIX userspace verdict mirror drifted from kernel semantics (LOW, fixed)
The BPF `socket_connect` hook enforces AF_UNIX default-deny with a dedicated
`unix_default_deny` bit and exact path allowlist matching. The userspace mirror used
for telemetry/explanations still checked the IPv4 `default_deny` flag and allowed
prefix matches. Kernel enforcement remained correct, but metrics, explanations, and
adaptive telemetry could mislabel UNIX socket decisions under mixed policies.
- **Fix:** the userspace mirror now checks `unix_default_deny` and exact
  allowlist equality. The daemon also injects its own control socket into the
  in-memory policy on initial load and reload, matching the BPF map loader's
  anti-lockout allowlist behavior. Feature-gated tests:
  `unix_default_deny_uses_exact_allowlist_match`,
  `unix_connects_follow_unix_default_deny_not_ipv4_default_deny`.

## Batch 10 — deployment unit socket exposure

### JG-RT-013 — systemd unit relied on implicit socket mode defaults (LOW, fixed)
The production systemd unit created `/run/jinnguard` with mode `0750`, but did not
pass the daemon's explicit `--socket-mode` flag or set a service `UMask`. That left
the control socket's final mode dependent on runtime defaults. In practice this
could drift toward either operator lockout (too restrictive for intended group
clients) or accidental exposure if deployment umask defaults changed.
- **Fix:** the unit now sets `UMask=0007` and starts the daemon with
  `--socket-mode=0770`, making the group-scoped control socket permission explicit.

## Batch 11 — production capability deprivilege

### JG-RT-014 — systemd unit did not enable post-attach capability hardening (MED, fixed)
The daemon has a kernel-validated hardening path that sets `no_new_privs`, drops
dangerous bounding-set capabilities, and reduces the effective/permitted capability
set after BPF attach. That path was still opt-in, and the shipped production unit
did not set `JINNGUARD_HARDEN_CAPS=1`, so a compromised long-running daemon could
retain live capability authority that was only needed during startup/attach.
- **Fix:** the production unit now enables `JINNGUARD_HARDEN_CAPS=1` by default,
  preserving the already-tested BPF attach flow while reducing post-attach blast
  radius.

## Batch 12 — Python SDK transport hardening

### JG-RT-015 — Python client trusted unbounded daemon response frames (LOW, fixed)
The Python SDK connected to the Unix socket with no timeout, ignored the response
frame version, and trusted the peer's declared response length before reading the
body. A stale/spoofed development socket or compromised local broker endpoint could
hang an integrating agent or force large client-side reads. The daemon path remains
the authoritative policy boundary, but SDK transport hardening prevents integration
code from turning a local socket problem into an agent-wide availability failure.
- **Fix:** the SDK now sets a socket timeout, rejects unsupported response frame
  versions, caps response frames at 4 MiB, detects truncated bodies, and auto-fills
  monotonically increasing sequence counters instead of reusing `1` for direct
  calls. Unit tests:
  `test_auto_sequence_counter_is_monotonic`,
  `test_oversized_response_frame_is_rejected_before_body_read`.

## Batch 13 — policy hot-reload fail-closed behavior

### JG-RT-016 — malformed hot-reload could replace active policy with permissive default (MED, fixed)
`load_policy_from_path` returned a compatibility default when the policy file was
missing or invalid, and the SIGHUP handler installed that result directly. An
operator typo or attacker-controlled policy-file corruption during hot-reload could
clear `deny_anonymous_agents`, agent nodes, and governed path scope instead of
keeping the last known-good policy. The raw remote policy refresh path also parsed
policy content through a hand-rolled branch that did not synchronize governed scope.
- **Fix:** added a fallible policy parser/loader for hot-reload paths. SIGHUP and
  raw remote refresh now install only successfully parsed policies; bad content
  logs an error and preserves the active policy/scope. Startup fallback remains
  compatible with existing local-dev behavior. Unit tests:
  `failed_policy_try_load_keeps_existing_governed_scope`,
  `successful_policy_try_load_installs_scope_and_anonymous_deny`.

## Batch 14 — lineage persistence migration safety

### JG-RT-017 — failed legacy lineage migration could delete replay/quota state (MED, fixed)
`LineageRegistry::load_or_create` migrated legacy JSON lineage files into SQLite,
but ignored per-row insert errors and removed the JSON file afterward. A partial
SQLite failure during upgrade could erase the only complete copy of lineage state,
resetting persisted replay monotonicity and sequence-quota accounting on restart.
- **Fix:** legacy JSON is now removed only after every lineage row is successfully
  copied into SQLite. Insert failure logs the affected key and keeps the JSON file
  for retry/recovery. Unit test:
  `lineage_legacy_json_kept_when_sqlite_migration_insert_fails`.

## Batch 15 — audit mirror failure integrity

### JG-RT-018 — SQLite audit mirror failure could fork the JSONL hash chain (MED, fixed)
`AuditLogger::log` appended the tamper-evident JSONL record first, then mirrored the
record into SQLite while ignoring mirror insert errors. The next append derived its
index/previous hash from SQLite before falling back to JSONL. If the JSONL append
succeeded but the SQLite mirror failed, the following event could reuse stale DB
state and write a broken JSONL hash link.
- **Fix:** the logger now derives the next chain link from JSONL first and treats
  SQLite as a query mirror/fallback. The two SQLite mirror inserts are transactional
  and mirror failures are logged without corrupting future JSONL links. Unit test:
  `audit_chain_continues_when_sqlite_mirror_insert_fails`.

## Batch 16 — broker URL host matching

### JG-RT-019 — broker network checks used substring/case-sensitive URL matching (MED, fixed)
The broker's network action guard accepted any string beginning with `https://`,
checked denied localhost/metadata patterns with case-sensitive substring scans, and
enforced constrained destinations with `url.contains(destination)`. That allowed
policy confusion such as `https://LOCALHOST/...` bypassing the localhost pattern or
`https://api.example.com.attacker.invalid/...` satisfying a constrained destination
of `api.example.com`.
- **Fix:** broker network requests now parse as HTTPS URLs, normalize the host, deny
  localhost/link-local hosts by host value, and match constrained destinations only
  by exact host or subdomain boundary. Unit tests:
  `broker_blocks_case_insensitive_localhost_url`,
  `constrained_network_destination_requires_host_match`.

## Batch 17 — MCP HTTP framing strictness

### JG-RT-020 — MCP parser accepted ambiguous HTTP request framing (LOW, fixed)
The MCP gateway supports fixed-length JSON-RPC requests, but its minimal HTTP parser
silently accepted duplicate `Content-Length`, invalid `Content-Length`, and
`Transfer-Encoding`. The proxy does not forward arbitrary inbound headers, so this
was not a direct upstream smuggling primitive, but ambiguous framing should fail
closed before governance parsing to avoid desync and parser-confusion edge cases.
- **Fix:** duplicate `Content-Length`, invalid lengths, and any
  `Transfer-Encoding` header now reject the request. Unit tests:
  `rejects_duplicate_content_length`,
  `rejects_transfer_encoding`.

## Batch 18 — remote policy refresh body limits

### JG-RT-021 — policy/fleet refresh could read unbounded remote response bodies (MED, fixed)
The raw policy-server refresh loop and signed fleet-policy refresh loop used bounded
request timeouts, but consumed response bodies with unbounded `text()`/JSON reads.
A malicious or compromised policy endpoint could stream an oversized body and drive
daemon memory growth even though signature/rollback checks would later reject bad
content.
- **Fix:** raw policy refresh, async fleet refresh, and the standalone blocking
  fleet client now enforce a 4 MiB response-body ceiling while reading. Unit test:
  `fetch_policy_bundle_rejects_oversized_response_without_content_length`.

## Batch 19 — BPF path-key truncation guard

### JG-RT-022 — overlong policy paths silently truncated into BPF map keys (MED, fixed)
Userspace encoded UNIX socket allowlist paths, allowed executable paths, and
basename deny keys into fixed 128-byte BPF map keys by truncating to 127 bytes.
Two distinct long paths with the same prefix could therefore collide in the kernel
maps, making policy behavior depend on a lossy encoding rather than the configured
path.
- **Fix:** kernel-map policy loaders now reject overlong paths/basenames instead of
  truncating them into BPF keys. Feature-gated unit tests:
  `path_key_checked_rejects_overlong_paths`,
  `name_key_bytes_checked_rejects_overlong_basenames`.

## Batch 20 — startup socket cleanup hardening

### JG-RT-023 — startup could unlink a non-socket at `--socket-path` (LOW, fixed)
Before binding the governance Unix socket, startup removed any filesystem node at
`--socket-path`. A typo or malicious service override pointing this argument at a
regular file would delete that file under daemon privileges. Symlinks were not
followed, but regular-file unlink was still an avoidable footgun in a privileged
service.
- **Fix:** startup now removes only an existing Unix socket and refuses regular
  files/symlinks/other node types. Unit tests:
  `remove_stale_unix_socket_removes_only_socket_nodes`,
  `remove_stale_unix_socket_refuses_regular_file`.

## Batch 21 — installer secret handling

### JG-RT-024 — installer passed the HMAC secret through process arguments (LOW, fixed)
The enterprise installer loaded `/etc/jinnguard/secret` into the session keyring
with `keyctl add ... "$(cat /etc/jinnguard/secret)" ...`. During installation, that
made the HMAC secret visible in the `keyctl` process arguments to sufficiently
privileged local process observers. The script also logged key-load success after a
failed `keyctl add` because the warning branch returned successfully.
- **Fix:** the installer now uses `keyctl padd` and feeds the secret over stdin,
  avoiding argv exposure. The success message is emitted only when the keyring load
  succeeds; otherwise the script logs the file-secret fallback.

## Batch 22 — CI token hardening

### JG-RT-025 — CI workflow inherited repository-default token permissions (LOW, fixed)
The main CI workflow did not set top-level `permissions`, so `GITHUB_TOKEN`
authority depended on repository defaults. If those defaults were write-capable,
ordinary build/test jobs would receive broader token scope than needed for
checkout and artifact handling.
- **Fix:** `.github/workflows/ci.yml` now clamps workflow token permissions to
  `contents: read`. The release workflow already used explicit per-job write/OIDC
  permissions only where publishing and signing require them.

## Batch 23 — #59 capstone verification round (post #61/#62 surface)

Verification pass over the high-signal leads from the interrupted Round 1. Each
was reproduced before fixing (failing-first regression test). JG-RT-026 (manifest
pinned-key) landed first via PR #54 and is now merged to `main`; its writeup is
retained here for a single consolidated record.

### JG-RT-026 — `--verify-manifests` trusted the in-directory pubkey (MED, fixed)
The Action Manifest verifier (#62) read the trusted Ed25519 public key from
`<audit-log>.manifests.pub` — a file in the **same directory as the log it is
verifying**. An attacker who can rewrite the audit log can also rewrite that
pubkey file: they regenerate a fully self-consistent set of manifests signed with
their *own* key, publish that key as `<log>.manifests.pub`, and the verifier
reports `OK`. That silently defeats the non-repudiation property the manifests
exist to provide — the forgery is indistinguishable from a genuine log unless the
verifier already holds the real key. (The original `forgery_with_different_key…`
test only passed because it manually restored the genuine pubkey, masking this.)
- **Fix:** `verify_manifests()` now takes an optional **pinned** public key and
  the CLI exposes `--manifest-pubkey <hex>`. When supplied (out-of-band), the
  in-directory pubkey is ignored and authenticity is checked against the pinned
  key — the only mode that resists a malicious log-holder. When omitted, the
  verifier falls back to the in-directory key for *convenience* (detects accidental
  corruption / non-malicious regeneration only) and the report/`ManifestVerification`
  is explicitly flagged `pubkey_pinned = false` ("self-consistency only"), so an
  unpinned pass can never be mistaken for proven authenticity. Regression test:
  `swapped_pubkey_forgery_defeated_only_by_pinned_key`. The genuine key is printed
  at daemon startup; THREAT_MODEL §12.1 documents the out-of-band key-distribution
  requirement.

### JG-RT-027 — GDPR "crypto-shred" was a logical DELETE, not key-destruction (MED, fixed → upgraded to REAL crypto-shredding)
`AuditLogger` stored personal data (executable path, argv) as **cleartext** columns
in `audit_pii`; `erase_subject` removed the rows with a plain SQLite `DELETE`.
Without `PRAGMA secure_delete` the deleted cell bytes remained in freed pages, so
the "shredded" plaintext was recoverable from the raw `.db` after erasure reported
success. More fundamentally, "crypto-shredding" implies *the data is encrypted and
the key is destroyed* — no key existed, so any surviving ciphertext copy (WAL,
backup, replica) stayed readable.
- **Repro (fail-first):** `audit_erasure_actually_wipes_plaintext_from_disk` (post-
  erase plaintext recoverable) and `pii_encrypted_at_rest_not_plaintext` — the
  latter greps the raw DB and finds `hunter2` **before any erasure**. Verified
  failing against the prior commit (`git show HEAD:…` + injected test →
  "plaintext PII 'hunter2' is present at rest"); passes on the fix.
- **Fix (real crypto-shred):** PII is now AEAD-sealed at rest under a **per-subject
  master key** kept only in a new `audit_pii_key` table. `read_subject_pii`
  decrypts on demand; `erase_subject` destroys the key row (and the ciphertext,
  under `secure_delete` as defence-in-depth). Destroying the key makes every
  ciphertext for the subject permanently undecryptable regardless of surviving
  copies — the actual Art. 17 crypto-shred guarantee. Chain hashes are untouched
  and `verify_chain` still passes identically before/after erasure.
- **Construction:** built only from the already-vetted `hmac`/`sha2` deps (no new
  supply-chain surface, `deny.toml` untouched, reproducible): per-record subkeys
  `enc/mac = HMAC(K, 0x01|0x02 ‖ nonce)`, HMAC-SHA256 counter-mode keystream
  (SP 800-108 / HKDF-Expand), encrypt-then-MAC with constant-time tag verify. A
  future hardening may swap to a named AEAD (`chacha20poly1305`) if the team
  accepts the added dependency; the key-lifecycle guarantee is identical.
- **Disclosure:** the #61 "crypto-shredding" claim is now **accurate** rather than
  needing a walk-back. Schema note: `audit_pii` changed shape (ciphertext columns
  + `audit_pii_key`); pre-existing rc-stage DBs must be re-created or migrated.

### JG-RT-028 — verify_chain() failed OPEN on a deleted/truncated audit log (MED, fixed)
`verify_chain()` read the JSONL chain with `unwrap_or_default()`; a missing or
empty file walked cleanly and returned `intact=true, entries=0`, driving the
tamper-evidence health gauge GREEN. An attacker who deletes the log to destroy
evidence was reported as "intact". (Tamper *within* a populated log was already
caught — only the absent/truncated case failed open.)
- **Repro:** `verify_chain_fails_closed_when_log_deleted_after_entries` — logs two
  entries, deletes the JSONL, observes `intact=true` before the fix.
- **Fix:** `verify_chain()` cross-checks the walked line count against the durable
  SQLite `audit_log` row count; a JSONL shorter than the committed count is
  reported `intact=false`. Test now passes.

### JG-RT-029 — Z3 invariant i32 saturation let an out-of-range value pass a `<=` check (LOW-MED, fixed)
`PolicyEngine::verify_policy_invariants` scaled operands with `(v * 1e6) as i32`.
Values whose scaled form exceeded i32 (`|v| ≳ 2147.48`) saturated to `i32::MAX`,
so two distinct large operands compared equal and an out-of-range value passed a
`<=`/`>=` check it should fail (fail-open). Reachable via caller-supplied
`context_vars` (e.g. through the MCP gateway) when an invariant is authored over a
caller-influenced variable; the daemon-guaranteed risk variables are all bounded
well inside the range, which limits real-world reach.
- **Repro:** `invariant_large_value_does_not_saturate_fail_open` and
  `invariant_two_distinct_huge_values_are_not_conflated` (ts_checker).
- **Fix:** out-of-range or non-finite operands are now rejected as a DENY
  (fail-closed) before the cast, instead of being silently clamped.

### JG-RT-030 — weak-RNG clock-seeded fallback undermined key material (MED, fixed)
`os_random_bytes` (audit salts + the new JG-RT-027 crypto-shred master keys) and
`os_random_32` (Ed25519 provenance signing seed) both silently downgraded to a
**deterministic clock-derived value** if `/dev/urandom` could not be opened. Once
JG-RT-027 landed, this became load-bearing: a predictable master key makes the
"destroy the key" crypto-shred meaningless (an attacker re-derives it), and a
predictable signing seed lets an attacker forge Action Manifest signatures.
- **Reach:** triggered when the CSPRNG is unavailable (minimal/broken container,
  seccomp, fd exhaustion). Cannot be faithfully reproduced in-process, so this is
  verified by construction + build, not a failing-first repro.
- **Fix:** both draws now use `getrandom(2)` first (no fd required, so fd
  exhaustion cannot force the weak path), then `/dev/urandom`, and **panic
  fail-closed** if neither is available — never a fabricated value. Guarded by an
  entropy smoke test (`os_random_bytes_are_high_entropy_not_clock_seeded`).

### JG-RT-031 — external audit-chain validator accepted tail-truncation (MED-HIGH disclosure, fixed)
`scripts/validate/verify_audit_chain.py` is the tool the public break-it challenge
tells reviewers to run to "prove it yourself." It genesis-anchors the chain and
catches insert/delete/reorder/content-tamper *within* the file and fails on an
empty file — but it had **no tail anchor**. An attacker who truncates the last K
entries (deleting the records of their own actions) leaves a valid shorter prefix,
and the script printed `AUDIT CHAIN VERIFIED ✓`. Same fail-open class as
JG-RT-028, but in the disclosure-critical external validator.
- **Repro (CONFIRMED):** built a valid 4-entry chain (incl. a "malicious" entry
  #3) with the script's own `recompute_hash`, dropped the last line → the script
  still reported `VERIFIED 3 entries — links intact`. Reproduced end-to-end via
  `main()` (exit 0).
- **Fix:** tail anchoring, in order — explicit `--expected-head <hash>` /
  `--min-entries <n>` pins, else an auto cross-check against the signed
  `<log>.manifests` sidecar (#62): if the chain's highest index is below the
  manifest's highest signed index, it FAILS with a truncation error and points to
  `ts_cli manifest verify` for the authoritative Ed25519 check. Absent any anchor
  the result now carries an explicit WARNING instead of an unqualified ✓, so it can
  no longer imply completeness it cannot prove.
- **Regression test:** `scripts/validate/test_verify_audit_chain_tail_truncation.py`
  (all three anchors + the unanchored-warning path).
- **Honesty note:** a bare hash chain fundamentally cannot detect tail-truncation
  without an external anchor; the stdlib count cross-check catches naive truncation
  and the signed-manifest verifier (`ts_cli manifest verify`) is authoritative. Both
  are now surfaced to the reviewer.

### JG-RT-032 — system-process immunity granted on spoofable/attacker fields (HIGH userspace, fixed)
`immunity_reason_for_observation` (main.rs:2281) emits `SIGNAL: ALLOW` and skips
ALL risk/Z3/policy evaluation for "system processes", logging the action as
`system_process_immunity`. It decided immunity from two attacker-controlled
inputs: (a) `observation.command_line[0]` = `/proc/<pid>/cmdline` argv[0], which a
process sets freely via execve (`argv[0]="bash"`), and (b) the client-supplied
`proposed_action` payload (`ShellCommand{command:"bash -c ..."}`). Either let an
authenticated governed agent obtain a rubber-stamp ALLOW with no risk evaluation.
Total bypass in audit-only / userspace-only deployments (no kernel BPF-LSM floor
as backstop); with the kernel floor it still defeats userspace mediation, the MCP
path, and pollutes the audit trail. `path_is_immune` also basename-matches, so a
renamed on-disk payload (`/home/agent/bash`) is immune — a harder residual, see
below.
- **Repro (CONFIRMED):** `immunity_ignores_spoofable_argv0` and
  `immunity_ignores_client_supplied_proposed_action` — both previously granted
  immunity, now denied; `immunity_still_honors_real_system_exe` confirms
  anti-lockout is preserved.
- **Fix:** immunity is now decided SOLELY by the kernel-attested `/proc/<pid>/exe`
  path from SO_PEERCRED (`observation_is_immune`), never by `command_line` or the
  proposed action. If `/proc/exe` is unreadable there is no trusted identity →
  fail closed (no immunity, normal policy path). Anti-lockout for real system
  binaries is unchanged (their real exe is in `IMMUNE_EXACT_PATHS`).
### JG-RT-032b — immunity basename fallback matched agent-writable paths (MED, fixed)
Residual of JG-RT-032: `path_is_immune` granted immunity to ANY path whose
*basename* was in `IMMUNE_PROCESS_NAMES`, regardless of directory. So a governed
agent that dropped a file literally named `bash`/`sh`/`cargo`/`systemd` in a
writable location (`/home`, `/tmp`, `/dev/shm`) and exec'd it — making its
kernel-attested `/proc/<pid>/exe` basename match — inherited full system-process
immunity.
- **Fix (`system_immunity.rs`):** the bare-basename fallback is now gated to
  `IMMUNE_EXEC_DIRS` (`/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`, `/lib`, `/usr/lib`,
  `/usr/local/bin`, `/usr/local/sbin`). A basename match is honored only when the
  exe lives under a trusted system root — writing there already requires root.
  Exact-path and systemd-prefix immunity are unchanged.
- **Anti-lockout preserved (low risk):** every real base-system binary's
  `/proc/exe` is under a trusted root, so no desktop component loses immunity;
  only agent-writable-location matches are dropped. Behavior change: dev tools in
  `$HOME` (e.g. `~/.cargo/bin/cargo`) lose *automatic* immunity — add them to
  `IMMUNE_EXACT_PATHS` if needed. **Still recommend a real Xfce/lightdm desktop
  smoke test before merge**, per the anti-lockout constraint, though this change
  only narrows immunity for non-system directories.
- **Tests:** `immunity_denies_basename_match_in_agent_writable_dir`,
  `immunity_honors_basename_match_in_trusted_system_dir`. ts_cli immunity 9/9.

### JG-RT-L3 — MCP gateway app-layer replay (HIGH, fixed)
The MCP gateway built `sequence_counter` from the **server clock**
(`mcp_gateway.rs:394`) and discarded the `validate_sequence` result
(`:646`, `let _ = lineage_ok;` — comment: "lenient on sequence
ordering"). There was no `ReplayGuard`. An attacker who intercepted or
observed any valid JSON-RPC request could retransmit it indefinitely:
each receive produced a fresh clock-derived seq, so nothing caught the
replay. The UDS wire daemon had an enforced `ReplayGuard` (JG-RT-002);
the gateway had none.
- **Repro (confirmed by source analysis):** Source code unambiguously
  shows the two gaps; a live gateway replay was not needed to confirm —
  the absence of `ReplayGuard` and the discarded `validate_sequence`
  result are structurally definitive.
- **Fix:** Added `McpReplayGuard` (bounded FIFO, same semantics as the
  UDS `ReplayGuard`), shared across all gateway connections via
  `Arc<Mutex<>>`. Nonce: explicit `jg_nonce` (u64) from params if the
  client supplies one; otherwise SHA-256(agent_id ‖ body) → u64
  (catches exact-body replays without requiring client changes). Replay
  detected → 403 `DENY_REPLAY_ATTACK` before governance runs.
  `let _ = lineage_ok` discard removed; lineage sequence errors now
  also return 403 `DENY_REPLAY_ATTACK`, mirroring the UDS path.
  No new deps — `sha2` was already present.
- **Tests (6 new):**
  `mcp_replay_guard_catches_replay`, `mcp_replay_guard_allows_distinct_nonces`,
  `mcp_replay_guard_evicts_at_capacity`, `body_nonce_is_deterministic`,
  `body_nonce_differs_by_agent`, `body_nonce_differs_by_body`.
  180+16+13 pass, clippy clean.

### JG-RT-L3b — MCP replay: body-hash fallback was weak (MED, fixed by Fable)
Cross-agent review (Fable) of the JG-RT-L3 fix (Antigravity), then fixed. The
explicit `jg_nonce` path was correct, but the default fallback — nonce =
SHA-256(agent_id ‖ raw_body) — had three problems (existing clients send no
`jg_nonce`, so the fallback is the common path):
- **False negative (bypass):** the raw-body hash covered attacker-controlled
  non-semantic bytes, so replaying a captured request while flipping the JSON-RPC
  `id` (or adding whitespace) produced a different hash → NOT flagged, yet the
  dangerous `method`+`params` were replayed. One-byte mutation defeated it.
- **Lineage regression (confirmed):** `seq = nonce` fed the content hash into
  lineage `validate_sequence`, which requires *strictly increasing* seq
  (`governance.rs:978`). A hash is not monotonic, so **~half of legitimate
  distinct requests were spuriously denied `sequence_replay`** — a real functional
  break the unit tests didn't exercise.
- **False positive:** two legitimately byte-identical requests were denied forever
  (unbounded dedup window).
- **Fix (`mcp_gateway.rs`):** (1) fallback nonce now hashes the **semantic
  identity** — `agent_id ‖ method ‖ canonical(params)` with `jg_nonce` removed —
  so non-semantic mutation no longer evades and key order is canonical; (2) the
  lineage `seq` is drawn from a **monotonic per-gateway counter**
  (`next_lineage_seq`), fully decoupled from the replay nonce, so
  `validate_sequence` never spuriously trips; (3) the replay guard is now
  **time-windowed** (`JINNGUARD_MCP_REPLAY_WINDOW_SECS`, default 120s) so a
  legitimate identical request after the window is allowed while a rapid replay is
  caught. `jg_nonce` remains the explicit strongest-guarantee override.
- **Tests:** `semantic_nonce_ignores_nonsemantic_bytes` (the bypass regression),
  `semantic_nonce_differs_by_semantic_content`, `semantic_nonce_excludes_jg_nonce_field`,
  `mcp_replay_guard_allows_repeat_after_window`,
  `mcp_lineage_seq_is_strictly_increasing_and_nonzero`. ts_cli 182 pass, clippy clean.
- **Residual:** content-based dedup still cannot distinguish a legit repeat from a
  replay across the window boundary without client freshness; strongest guarantee
  needs `jg_nonce` or mTLS. Documented.

### JG-RT-B1 — BPF ringbuf-full deny path: `barrier_var` consistency (LOW, fixed — all 4 sites)
Antigravity's B1 added the `barrier_var` guard to `jg_socket_sendmsg.c` (stops
clang -O2 lowering `cond ? -EPERM : 0` into an unbounded `BPF_NEG` the verifier
can reject at load → silent enforcement gap). Fable review found **three sibling
sites with the identical `if (!req) return audit_only ? 0 : -JG_EPERM;`** that were
NOT fixed: `jg_bprm_check_security.c` (the exec allowlist — a silent load failure
there disables exec enforcement), `jg_inode_unlink.c`, `jg_inode_create.c`.
- **Fix:** applied the same `barrier_var` branch pattern to all three, matching
  `socket_connect`/`sendmsg`. All four now consistent.
- **Verification:** all four compile clean with `clang -target bpf -O2` here.
  Compilation is NOT the verifier — the authoritative check is the `build-ebpf`
  CI gate + the real-kernel matrix load (5.14/6.12/6.17), which this sandbox can't
  run. Must pass those before merge.

### JG-RT-L6a — startup policy load failed OPEN to a permissive default (MED, fixed)
`load_policy_from_path` (`main.rs`) returned a **permissive** default
(`deny_anonymous_agents=false`) whenever the policy was missing, unreadable, or
malformed at startup — so a corrupted or absent `/etc/jinnguard/policy.yaml`
silently admitted unregistered agents. Asymmetric with the hot-reload path, which
keeps the last-good policy on error.
- **Fix:** the startup fallback now fails **CLOSED**
  (`deny_anonymous_agents=true`) and logs a loud `[startup][WARN]` distinguishing
  *missing* from *malformed*. Local dev can restore the old permissive default
  with `JINNGUARD_PERMISSIVE_STARTUP_DEFAULT=1`. An operator wanting open access
  still passes `--allow-anonymous`, which layers on top independently.
- **Tests:** `startup_policy_fallback_fails_closed_on_missing_or_malformed`
  (missing + malformed both deny; env opt-out restores permissive). ts_cli 185
  pass, clippy clean.

### Leads still open
- _(none in the reviewed userspace surfaces; see "needs external validation" below)_

### Needs external / non-sandbox validation before merge
- **BPF verifier load** for JG-RT-B1 (4 hooks) — needs the `build-ebpf` CI gate +
  real-kernel matrix (5.14/6.12/6.17); compiles clean locally but the verifier
  cannot run here.
- **JG-RT-032b desktop smoke** — a real Xfce/lightdm session to confirm no
  anti-lockout regression (the change only narrows immunity for non-system dirs,
  so risk is low, but the constraint requires the check).
- **`deploy/bootstrap.sh`** end-to-end on a bare host + the non-apt distros.
- **PR #55** CI must be freshly green before merge (no `gh`/network in-sandbox);
  JG-RT-026 already merged via PR #54.

## Closeout

- Internal red-team batches JG-RT-001 through JG-RT-032 (plus JG-RT-L3/L3b/L6a/B1)
  are fixed or explicitly documented as defense-in-depth residuals. JG-RT-026
  (manifest pinned-key) merged to `main` via PR #54; JG-RT-027..032 + JG-RT-L3/L3b
  + JG-RT-B1 + JG-RT-L6a (capstone verification round) are on `redteam-verify`
  (PR #55) with failing-first regression tests.
- Post-merge real-kernel validation passed on the supported self-hosted matrix:
  Debian 13 / kernel 6.12, Ubuntu 24.04 / kernel 6.17, and AlmaLinux 9.8 /
  kernel 5.14. The AlmaLinux timeout accounting fix in PR #33 preserved hard
  failures for fail-open, incorrect verdicts, and denied-side timeouts.
- No known open findings remain in the reviewed UDS, MCP, lineage, quota, fleet,
  BPF map-loading, deployment, or CI-permission surfaces. BPF/C + Python surfaces
  scanned in Batch 24 (see above).
