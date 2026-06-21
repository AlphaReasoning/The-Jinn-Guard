#!/usr/bin/env bash
#
# scripts/validate/kernel_floor_demo.sh
#
# The kernel enforcement floor, demonstrated — the one proof the userspace
# validation suite (scripts/validate/validate.py) CANNOT show.
#
# The userspace suite proves the daemon makes correct, audited, deterministic
# decisions for agents that *cooperate* (send a signed intent over the socket).
# This demo proves the harder thing: a governed agent that **bypasses the socket
# entirely** — never asks the guard, just calls the syscall directly — is still
# blocked, by the **kernel** (BPF-LSM), not by the agent's good behaviour.
#
# It drives the real privileged enforcement path (ts_cli/tests/kernel_lsm.rs):
# enforcement is armed and scoped to a throwaway cgroup, a probe process enters
# that cgroup, and then performs direct execve / connect / file operations that
# the policy denies. The kernel returns EPERM. Nothing goes through the daemon's
# socket.
#
# REQUIREMENTS (a real host/VM such as jinn1 — NOT a container):
#   - root
#   - a kernel with BPF-LSM enabled and `bpf` in the active LSM list
#   - cgroup v2 mounted at /sys/fs/cgroup
#   - clang, bpftool (linux-tools), and a built ts_cli (enterprise feature)
#
# Run (after building — see the companion paste block / README):
#   sudo bash scripts/validate/kernel_floor_demo.sh
#
# No `set -e`: we want every preflight check to report clearly rather than abort.
set -uo pipefail

c_info() { printf '\033[2m%s\033[0m\n' "$*"; }
c_ok()   { printf '\033[1;32m%s\033[0m\n' "$*"; }
c_bad()  { printf '\033[1;31m%s\033[0m\n' "$*"; }
c_head() { printf '\n\033[1m%s\033[0m\n' "$*"; }

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT" || { c_bad "cannot cd to repo root"; exit 2; }

c_head "Jinn Guard — kernel enforcement floor demo"
c_info "Proving: a governed agent that bypasses the userspace socket and calls the"
c_info "syscall directly is still blocked by the kernel (BPF-LSM), not by cooperation."

# --------------------------------------------------------------------------- #
# Preflight — fail loudly and specifically, so the environment is easy to fix.
# --------------------------------------------------------------------------- #
fail=0
c_head "[preflight]"

if [[ "$(id -u)" -ne 0 ]]; then
  c_bad "  must run as root (sudo bash $0)"; fail=1
else
  c_ok  "  root: ok"
fi

if [[ -e /sys/fs/cgroup/cgroup.controllers ]]; then
  c_ok  "  cgroup v2: ok"
else
  c_bad "  cgroup v2 not mounted at /sys/fs/cgroup"; fail=1
fi

if [[ -r /sys/kernel/security/lsm ]] && grep -q 'bpf' /sys/kernel/security/lsm; then
  c_ok  "  BPF-LSM active: $(cat /sys/kernel/security/lsm)"
else
  c_bad "  'bpf' is not in the active LSM list (/sys/kernel/security/lsm)."
  c_bad "  Add it: boot with lsm=...,bpf  (e.g. GRUB lsm=lockdown,yama,bpf), then reboot."
  fail=1
fi

for tool in clang bpftool; do
  if command -v "$tool" >/dev/null 2>&1; then c_ok "  $tool: $(command -v "$tool")"
  else c_bad "  $tool not found in PATH"; fail=1; fi
done

# Resolve the build user (so cargo runs with the right toolchain/env).
BUILD_USER="${SUDO_USER:-root}"
BIN="$REPO_ROOT/target/debug/ts_cli"

# Run a cargo command as the build user (loads their PATH/CARGO_HOME/rustup), or
# directly if there is no separate invoking user.
run_cargo() {
  if [[ "$BUILD_USER" != "root" ]]; then
    sudo -u "$BUILD_USER" -H bash -lc "cd '$REPO_ROOT' && $*"
  else
    bash -lc "cd '$REPO_ROOT' && $*"
  fi
}

if [[ $fail -ne 0 ]]; then
  c_bad "\n[preflight] environment not ready — fix the items above and re-run."
  exit 2
fi

# --------------------------------------------------------------------------- #
# Build the BPF object + daemon if needed (idempotent).
# --------------------------------------------------------------------------- #
c_head "[build] eBPF LSM object + ts_cli (enterprise)"
export PATH="$PATH:/usr/sbin"
c_info "  make -C bpf install"
make -C bpf install || { c_bad "  BPF install failed (clang/bpftool/vmlinux.h?)"; exit 3; }

c_info "  building ts_cli (as $BUILD_USER)"
run_cargo "cargo build -p ts_cli --features enterprise" || { c_bad "  cargo build failed"; exit 3; }
[[ -x "$BIN" ]] || { c_bad "  built binary not found at $BIN"; exit 3; }
c_ok  "  built: $BIN"

# --------------------------------------------------------------------------- #
# Run the real privileged enforcement tests (the socket-bypass proof).
# --------------------------------------------------------------------------- #
c_head "[run] armed kernel-LSM enforcement (direct syscalls, no socket)"
c_info "  The probe enters a governed cgroup, then directly attempts:"
c_info "    • connect() to a denied IP        → expect kernel EPERM"
c_info "    • write()/unlink() a denied path   → expect kernel EPERM"
c_info "    • execve() a non-allowlisted binary→ expect kernel EPERM"
c_info "  None of these go through the daemon socket. Enforcement is the kernel."
echo

# Compile the test binary as the build user (cargo + registry resolve there), then
# run the raw binary as root — no cargo needed at root, no root-owned target churn.
c_info "  compiling the kernel_lsm test binary (as $BUILD_USER)"
run_cargo "cargo test -p ts_cli --features enterprise --test kernel_lsm --no-run" \
  || { c_bad "  compiling kernel_lsm test failed"; exit 3; }

TESTBIN="$(find "$REPO_ROOT/target/debug/deps" -maxdepth 1 -type f -executable \
  -name 'kernel_lsm-*' ! -name '*.d' -printf '%T@ %p\n' 2>/dev/null \
  | sort -rn | head -1 | cut -d' ' -f2-)"
if [[ -z "$TESTBIN" || ! -x "$TESTBIN" ]]; then
  c_bad "  could not locate the compiled kernel_lsm test binary under target/debug/deps"
  exit 3
fi
c_ok  "  test binary: $TESTBIN"
echo

# Already root; execute the raw test binary directly.
export PATH="$PATH:/usr/sbin"
JINNGUARD_TEST_BINARY="$BIN" "$TESTBIN" --ignored --test-threads=1 --nocapture
rc=$?

c_head "[result]"
if [[ $rc -eq 0 ]]; then
  c_ok  "  PASS — the kernel blocked every socket-bypassing attempt (0 fail-open)."
  c_ok  "  This is the guarantee that holds even when the agent does not cooperate."
else
  c_bad "  FAIL (exit $rc) — see output above. Paste the log back for diagnosis."
fi
exit $rc
