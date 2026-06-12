# Changelog

All notable changes to Jinn Guard are documented here. This project is a
validated research prototype / controlled-pilot MVP; see
[`THREAT_MODEL.md`](THREAT_MODEL.md) for the security model and honest scope.

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
- **CVE-2026-002 (Critical) — filesystem policy bypass via relative paths.**
  Kernel now resolves the full absolute path before the denylist check
  (`jg_read_dentry_path`, depth-12 dentry walk). Verified audit-only and armed.
- **CVE-2026-001 (High) — execve bypass via interpreter chains.** Governed agents
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
- Sub-mount filesystem paths resolve relative to their mount root; root-fs paths
  resolve absolutely.
- Interpreter chains mitigated, not eliminated.
- HMAC key rotation not yet automated.

See [`THREAT_MODEL.md`](THREAT_MODEL.md) §7 and §9 for the full list and the path
to audited GA.
