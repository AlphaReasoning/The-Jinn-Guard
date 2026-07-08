#!/usr/bin/env bash
#
# run_professor_validation.sh — one-command validation of Jinn Guard.
#
# WHAT THIS IS:
#   A single entry point that detects what your machine can do and runs the
#   matching validation tiers, then prints a summary. It is capability-aware:
#   tiers that need Docker or root are skipped (clearly) when unavailable, so it
#   is safe to run anywhere — including without root.
#
# TIERS:
#   1. Build + full automated test suite      (always; no root, no Docker)
#   2. Mandatory-mediation in Docker          (if Docker is installed)
#   3. Kernel path resolution, AUDIT-ONLY     (if root + BPF-LSM; blocks nothing)
#   4. Kernel ENFORCEMENT (allow/deny)        (only with --arm)
#
# SAFETY:
#   Tiers 1-3 cannot block anything and cannot lock you out. Tier 4 arms real
#   kernel denial, but enforcement is CGROUP-SCOPED to a dedicated test cgroup
#   the suite creates and moves only its own probe processes into. Every other
#   task on the host — including your desktop session — is structurally out of
#   scope and passes through untouched. A wrong scope makes the test FAIL, not
#   your machine. Belt-and-suspenders: a hard 10-minute watchdog tears the test
#   down even if it hangs, and a reboot clears all kernel state regardless.
#   Tier 4 still needs cgroup v2 (the default on modern Linux) and is OFF by
#   default; pass --arm to enable it.
#
# USAGE:
#   bash scripts/run_professor_validation.sh            # safe tiers (1-3)
#   sudo bash scripts/run_professor_validation.sh       # add tier 3 (root)
#   sudo bash scripts/run_professor_validation.sh --arm # add tier 4 (cgroup-scoped)
#
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT" || { echo "fatal: cannot cd to repo root '$REPO_ROOT'" >&2; exit 1; }
ARM=0
[[ "${1:-}" == "--arm" ]] && ARM=1

OS="$(uname -s 2>/dev/null || echo unknown)"

# On macOS, Homebrew's Z3 and LLVM are not on the default linker/bindgen search
# path, so `ts_checker` fails to link (`ld: library 'z3' not found`) and the Z3
# bindings can't find libclang. Export the paths if the kegs are present. This is
# a no-op on Linux and harmless when Homebrew isn't installed.
if [[ "$OS" == "Darwin" ]]; then
  for pfx in /opt/homebrew /usr/local; do
    if [[ -d "$pfx/opt/z3/lib" ]]; then
      export LIBRARY_PATH="$pfx/opt/z3/lib:${LIBRARY_PATH:-}"
      export DYLD_LIBRARY_PATH="$pfx/opt/z3/lib:${DYLD_LIBRARY_PATH:-}"
    fi
    [[ -d "$pfx/opt/llvm/lib" ]] && export LIBCLANG_PATH="$pfx/opt/llvm/lib:${LIBCLANG_PATH:-}"
  done
fi

c_hdr()  { printf '\n\033[1;36m========== %s ==========\033[0m\n' "$*"; }
c_ok()   { printf '\033[1;32m  [OK]   %s\033[0m\n' "$*"; }
c_skip() { printf '\033[1;33m  [SKIP] %s\033[0m\n' "$*"; }
c_fail() { printf '\033[1;31m  [FAIL] %s\033[0m\n' "$*"; }
c_info() { printf '         %s\n' "$*"; }

# Results accumulators. Indirect per-tier variables (RESULT_T1…RESULT_T4) instead
# of an associative array, so this runs on macOS's stock bash 3.2 as well as 4+.
mark() { printf -v "RESULT_$1" '%s' "$2"; }   # mark <tier> <PASS|FAIL|SKIP>
res()  { local v="RESULT_$1"; printf '%s' "${!v:-}"; }   # res <tier> -> status (empty if unset)

# ---------------------------------------------------------------------------
c_hdr "Environment"
have() { command -v "$1" >/dev/null 2>&1; }
IS_ROOT=0; [[ ${EUID:-$(id -u)} -eq 0 ]] && IS_ROOT=1
# cargo may belong to the invoking (non-root) user; resolve it.
CARGO_USER="${SUDO_USER:-$(id -un)}"
run_cargo() {
  if [[ $IS_ROOT -eq 1 && -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]]; then
    sudo -u "$SUDO_USER" -H bash -lc "cd '$REPO_ROOT' && cargo $*"
  else
    bash -lc "cd '$REPO_ROOT' && cargo $*"
  fi
}
run_cargo --version >/dev/null 2>&1 && HAS_CARGO=1 || HAS_CARGO=0
HAS_DOCKER=0; ( have docker && docker info >/dev/null 2>&1 ) && HAS_DOCKER=1
HAS_BPFLSM=0; grep -qw bpf /sys/kernel/security/lsm 2>/dev/null && HAS_BPFLSM=1
HAS_CLANG=0; have clang && HAS_CLANG=1
KVER="$(uname -r 2>/dev/null || echo unknown)"

c_info "kernel:      $KVER"
c_info "root:        $([[ $IS_ROOT -eq 1 ]] && echo yes || echo 'no (tiers 3-4 need sudo)')"
c_info "cargo:       $([[ $HAS_CARGO -eq 1 ]] && echo "yes (user: $CARGO_USER)" || echo 'NO — install rustup')"
c_info "docker:      $([[ $HAS_DOCKER -eq 1 ]] && echo yes || echo 'no (tier 2 skipped)')"
c_info "BPF-LSM:     $([[ $HAS_BPFLSM -eq 1 ]] && echo yes || echo 'no (tiers 3-4 skipped)')"
c_info "clang:       $([[ $HAS_CLANG -eq 1 ]] && echo yes || echo 'no (tiers 3-4 skipped)')"
c_info "arm tier 4:  $([[ $ARM -eq 1 ]] && echo 'YES (real denial — cgroup-scoped to the test only)' || echo 'no (default; pass --arm to enable)')"

if [[ $HAS_CARGO -eq 0 ]]; then
  c_fail "cargo (Rust) is required even for tier 1. Install rustup as a normal user and re-run."
  exit 1
fi

# ---------------------------------------------------------------------------
c_hdr "Tier 1 — build + full automated test suite (no root, no Docker)"
# The daemon (ts_cli) and eBPF layer are Linux-only. On other hosts (e.g. a
# reviewer's macOS laptop), Tier 1 validates the portable crates — the Z3 SMT
# engine (ts_checker) and the wire-protocol parser (ts_wire) — which is the most
# that can be checked without a Linux kernel. Full enforcement needs tiers 2-4.
if [[ "$OS" == "Linux" ]]; then
  T1_BUILD="build --release"
  T1_TEST="test --workspace"
else
  c_info "non-Linux host ($OS): ts_cli + eBPF are Linux-only; validating the"
  c_info "portable crates only (ts_checker SMT engine, ts_wire protocol)."
  c_info "Run tiers 2-4 on a Linux host for full enforcement validation."
  T1_BUILD="build --release -p ts_checker -p ts_wire"
  T1_TEST="test -p ts_checker -p ts_wire"
fi
if run_cargo $T1_BUILD >/dev/null 2>&1; then
  c_ok "release build succeeded"
else
  c_fail "release build failed; run 'cargo $T1_BUILD' to see the error"
  mark T1 FAIL
fi
T1_OUT="$(run_cargo $T1_TEST 2>&1)"
echo "$T1_OUT" | grep -E "test result:" | sed 's/^/         /'
if echo "$T1_OUT" | grep -q "test result: FAILED"; then
  c_fail "one or more test suites failed"
  mark T1 FAIL
else
  PASSES=$(echo "$T1_OUT" | grep -oE "test result: ok\. [0-9]+ passed" | grep -oE "[0-9]+ passed" | grep -oE "[0-9]+" | awk '{s+=$1} END {print s}')
  c_ok "all automated tests passed (~${PASSES} tests across unit + integration + swarm-attack suites)"
  mark T1 PASS
fi

# ---------------------------------------------------------------------------
c_hdr "Tier 2 — mandatory mediation in Docker"
if [[ $HAS_DOCKER -eq 0 ]]; then
  c_skip "Docker not available; skipping. (Install docker.io to run this tier.)"
  mark T2 SKIP
else
  c_info "Building containers and running the locked-agent probes (first build is slow)..."
  if bash scripts/validate_m5_mandatory_mediation.sh >/tmp/jg-prof-m5.log 2>&1; then
    c_ok "mandatory mediation enforced — all 7 locked-agent probes passed"
    grep -E "\[(PASS|FAIL)\] " /tmp/jg-prof-m5.log | sed 's/^/         /' | tail -7
    mark T2 PASS
  else
    c_fail "mandatory-mediation validation did not pass; see /tmp/jg-prof-m5.log"
    mark T2 FAIL
  fi
fi

# ---------------------------------------------------------------------------
c_hdr "Tier 3 — kernel path resolution (AUDIT-ONLY; blocks nothing)"
if [[ $IS_ROOT -eq 0 ]]; then
  c_skip "needs root; re-run with sudo to include this tier."
  mark T3 SKIP
elif [[ $HAS_BPFLSM -eq 0 || $HAS_CLANG -eq 0 ]]; then
  c_skip "needs BPF-LSM enabled + clang installed; skipping."
  mark T3 SKIP
else
  c_info "Loading the LSM hooks in safe mode and confirming full-path resolution..."
  if bash scripts/validate_m2_path_resolution.sh >/tmp/jg-prof-m2.log 2>&1; then
    c_ok "kernel resolves full file paths (JG-ADV-2026-002 fix) — audit-only, nothing blocked"
    mark T3 PASS
  else
    c_fail "audit-only path-resolution validation did not pass; see /tmp/jg-prof-m2.log"
    mark T3 FAIL
  fi
fi

# ---------------------------------------------------------------------------
c_hdr "Tier 4 — kernel ENFORCEMENT allow/deny (arms real denial)"
if [[ $ARM -eq 0 ]]; then
  c_skip "off by default. Re-run with '--arm' to validate real allow/deny (cgroup-scoped to the test; needs cgroup v2)."
  mark T4 SKIP
elif [[ $IS_ROOT -eq 0 || $HAS_BPFLSM -eq 0 || $HAS_CLANG -eq 0 ]]; then
  c_skip "needs sudo + BPF-LSM + clang; skipping."
  mark T4 SKIP
elif [[ ! -e /sys/fs/cgroup/cgroup.controllers ]]; then
  c_skip "cgroup v2 not mounted at /sys/fs/cgroup; Tier 4 scoping needs it. Skipping."
  mark T4 SKIP
else
  printf '\033[1;33m  Arming real kernel denial, CGROUP-SCOPED to a dedicated test cgroup.\n'
  printf '  Only the suite'\''s own probe processes are governed; the rest of this host\n'
  printf '  (your desktop included) is out of scope. A 10-min watchdog + reboot are\n'
  printf '  the safety net. cgroup v2 detected.\033[0m\n'
  if ! have bpftool; then c_info "installing bpftool..."; apt-get install -y bpftool >/dev/null 2>&1 || true; fi
  c_info "regenerating vmlinux.h, building + installing LSM objects..."
  bpfarch=x86; [ "$(uname -m)" = aarch64 ] && bpfarch=arm64
  ( cd bpf && bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h 2>/dev/null \
    && for f in lsm/jg_socket_connect lsm/jg_socket_sendmsg lsm/jg_bprm_check_security lsm/jg_inode_create lsm/jg_inode_unlink; do
         clang -O2 -g -target bpf -D__TARGET_ARCH_${bpfarch} -I/usr/include -I. -c "$f.c" -o "$f.o" || exit 1; done ) \
    && install -d /usr/lib/jinnguard/lsm \
    && install -m 0644 bpf/lsm/*.o /usr/lib/jinnguard/lsm/ \
    || { c_fail "LSM object build/install failed"; mark T4 FAIL; }

  if [[ "$(res T4)" != "FAIL" ]]; then
    c_info "building enterprise daemon (as $CARGO_USER)..."
    run_cargo build --features enterprise >/tmp/jg-prof-build.log 2>&1 || { c_fail "enterprise build failed (see /tmp/jg-prof-build.log)"; mark T4 FAIL; }
  fi

  # Compile the kernel test binary AS THE USER (cargo/rustup live in the user's
  # PATH, not root's) and run the compiled binary directly as root. The test
  # itself needs root for BPF + cgroup setup, but needs no cargo at run time.
  TEST_BIN=""
  if [[ "$(res T4)" != "FAIL" ]]; then
    c_info "building kernel allow/deny test binary (as $CARGO_USER)..."
    if run_cargo test --features enterprise --test kernel_lsm --no-run >/tmp/jg-prof-testbuild.log 2>&1; then
      TEST_BIN="$(find "$REPO_ROOT/target/debug/deps" -maxdepth 1 -type f -executable -name 'kernel_lsm-*' -printf '%T@ %p\n' 2>/dev/null | sort -rn | head -1 | cut -d' ' -f2-)"
      [[ -n "$TEST_BIN" ]] || { c_fail "could not locate compiled kernel_lsm test binary (see /tmp/jg-prof-testbuild.log)"; mark T4 FAIL; }
    else
      c_fail "kernel test build failed (see /tmp/jg-prof-testbuild.log)"; mark T4 FAIL
    fi
  fi

  if [[ "$(res T4)" != "FAIL" ]]; then
    BIN="$REPO_ROOT/target/debug/ts_cli"
    c_info "running the project's kernel allow/deny suite (10-min watchdog)..."
    # A hard timeout guarantees enforcement is removed even if a test hangs.
    if timeout --signal=KILL 600 env JINNGUARD_TEST_BINARY="$BIN" JINN_KERNEL_LSM_OPS=500 \
         "$TEST_BIN" --ignored --test-threads=1 --nocapture \
         >/tmp/jg-prof-m5b.log 2>&1; then
      c_ok "kernel enforcement validated — allow/deny correct across execve, TCP, UDP, create, unlink"
      grep -E "\[KERNEL_LSM_" /tmp/jg-prof-m5b.log | sed 's/^/         /'
      mark T4 PASS
    else
      c_fail "kernel enforcement suite failed or timed out; see /tmp/jg-prof-m5b.log"
      mark T4 FAIL
    fi
  fi
fi

# ---------------------------------------------------------------------------
c_hdr "Summary"
overall=0
for t in T1 T2 T3 T4; do
  case "$(res "$t")" in
    PASS) printf '  \033[1;32m%-4s PASS\033[0m\n' "$t" ;;
    FAIL) printf '  \033[1;31m%-4s FAIL\033[0m\n' "$t"; overall=1 ;;
    *)    printf '  \033[1;33m%-4s SKIP\033[0m\n' "$t" ;;
  esac
done
echo
if [[ $overall -eq 0 ]]; then
  printf '\033[1;32mAll executed tiers PASSED. Skipped tiers need Docker/root/--arm (see above).\033[0m\n'
else
  printf '\033[1;31mOne or more tiers FAILED — logs are under /tmp/jg-prof-*.log.\033[0m\n'
fi
exit $overall
