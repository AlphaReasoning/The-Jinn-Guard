#!/usr/bin/env bash
#
# validate_m2_path_resolution.sh — AUDIT-ONLY validation for M2 (CVE-2026-002).
#
# WHAT THIS DOES, IN PLAIN WORDS:
#   It loads the Jinn Guard kernel programs in SAFE MODE (audit-only). In safe
#   mode the kernel programs are wired to ALLOW everything — they only watch and
#   write notes, they never block. We then create a deeply nested file and check
#   that Jinn Guard wrote down its FULL address (e.g.
#   /tmp/jinnguard-test/alpha/beta/gamma/secret.txt) instead of just the short
#   name (secret.txt). That full address is the M2 fix.
#
# WHY IT IS SAFE ON YOUR DESKTOP:
#   - It only ever runs in SAFE MODE (JINNGUARD_SAFE_MODE=1). The kernel programs
#     set their audit-only switch BEFORE they attach, and every hook returns
#     "allow". Nothing can be denied, so you cannot be locked out.
#   - It uses temporary files under /tmp and a temporary socket. It does not
#     touch /run/jinnguard, your real policy, or your installed service.
#   - When it finishes (or if anything fails) it stops the daemon, which detaches
#     the kernel programs. Nothing stays loaded.
#
# IF THE KERNEL REJECTS THE PROGRAM:
#   The Linux "verifier" inspects BPF code at load time. If it rejects our new
#   code, the daemon log will show the error. This script prints that log. Copy
#   it back to Claude and it will fix the code — this is normal BPF iteration.
#
# HOW TO RUN (in your separate root terminal, from the repo root):
#   sudo bash scripts/validate_m2_path_resolution.sh
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="/tmp/jg-m2-validate"
LOG="$WORK/daemon.log"
TEST_DIR="/tmp/jinnguard-test/alpha/beta/gamma"
TEST_FILE="$TEST_DIR/secret.txt"
EXPECTED_PATH="$TEST_FILE"
LSM_INSTALL_DIR="/usr/lib/jinnguard/lsm"
DAEMON_PID=""

say()  { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m   OK: %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m   ! %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31m   FAIL: %s\033[0m\n' "$*" >&2; exit 1; }

# Run cargo as the user who invoked sudo (rustup installs cargo into that user's
# ~/.cargo, which root's PATH does not see). A login shell picks up their PATH.
# This also keeps target/ owned by the user instead of root.
run_cargo() {
  if [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]]; then
    sudo -u "$SUDO_USER" -H bash -lc "cd '$REPO_ROOT' && cargo $*"
  else
    ( cd "$REPO_ROOT" && cargo "$@" )
  fi
}

cleanup() {
  if [[ -n "$DAEMON_PID" ]] && kill -0 "$DAEMON_PID" 2>/dev/null; then
    kill "$DAEMON_PID" 2>/dev/null || true
    wait "$DAEMON_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
say "Step 1/7 — checks"
[[ $EUID -eq 0 ]] || die "run this with sudo (root is needed to load kernel programs)."
grep -qw bpf /sys/kernel/security/lsm 2>/dev/null \
  || die "BPF-LSM is not enabled on this kernel. Add 'lsm=...,bpf' to the boot line and reboot."
ok "running as root and BPF-LSM is enabled."

say "Step 2/7 — build tools"
missing=()
command -v clang   >/dev/null 2>&1 || missing+=(clang)
command -v bpftool >/dev/null 2>&1 || missing+=(bpftool)
[[ -d /usr/include/bpf ]]          || missing+=(libbpf-dev)
if (( ${#missing[@]} )); then
  warn "missing: ${missing[*]}"
  warn "installing build tools via apt (clang libbpf-dev bpftool)..."
  apt-get update -y && apt-get install -y clang libbpf-dev bpftool || \
    die "could not install build tools; install ${missing[*]} and re-run."
fi
# cargo belongs to the invoking user (rustup), not root — check it that way.
if ! run_cargo --version >/dev/null 2>&1; then
  die "cargo (Rust) not found for user '${SUDO_USER:-root}'. Install rustup as that user, then re-run."
fi
ok "clang, bpftool, libbpf present; cargo reachable as ${SUDO_USER:-root}."

mkdir -p "$WORK"

say "Step 3/7 — generate kernel headers + build the kernel programs"
# Use THIS machine's kernel BTF so the programs match your exact kernel.
bpftool btf dump file /sys/kernel/btf/vmlinux format c > "$REPO_ROOT/bpf/vmlinux.h" \
  || die "could not dump kernel BTF (need a kernel built with CONFIG_DEBUG_INFO_BTF)."
ok "regenerated bpf/vmlinux.h from /sys/kernel/btf/vmlinux"

cd "$REPO_ROOT/bpf"
BUILT=()
for src in lsm/jg_socket_connect.c lsm/jg_socket_sendmsg.c lsm/jg_bprm_check_security.c \
           lsm/jg_inode_create.c lsm/jg_inode_unlink.c; do
  obj="${src%.c}.o"
  clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I/usr/include -I. -c "$src" -o "$obj" \
    || die "clang failed to compile $src"
  BUILT+=("$obj")
done
ok "compiled ${#BUILT[@]} LSM objects."

install -d "$LSM_INSTALL_DIR"
install -m 0644 "${BUILT[@]}" "$LSM_INSTALL_DIR/"
ok "installed objects to $LSM_INSTALL_DIR"

say "Step 4/7 — build the daemon (kernel feature, as ${SUDO_USER:-root})"
if ! run_cargo build --release --features kernel_telemetry; then
  die "daemon build failed; run 'cargo build --release --features kernel_telemetry' as ${SUDO_USER:-root} to see why."
fi
[[ -x "$REPO_ROOT/target/release/ts_cli" ]] \
  || die "expected binary $REPO_ROOT/target/release/ts_cli not found after build."
ok "built target/release/ts_cli"

say "Step 5/7 — start the daemon in SAFE MODE (audit-only, blocks nothing)"
# Generate a throwaway HMAC secret. Its value is irrelevant here (we send no
# signed proposals — this is LSM-only validation); the daemon just needs the
# file to exist. Use od so we don't depend on xxd being installed.
head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$WORK/secret"
cat > "$WORK/policy.yaml" <<'YAML'
global_safety_ceiling: 95.0
enforcement_scope:
  governed_path_prefixes: []
agent_nodes: []
YAML

JINNGUARD_SAFE_MODE=1 ENABLE_EXPLAINABILITY=1 JINN_GUARD_MCP_PORT=48750 \
  "$REPO_ROOT/target/release/ts_cli" \
    --socket-path "$WORK/jg.sock" \
    --policy-file "$WORK/policy.yaml" \
    --secret-file "$WORK/secret" \
    --lineage-file "$WORK/lineage.json" \
    --audit-log "$WORK/audit.log" \
    --mcp-port 48750 \
  > "$LOG" 2>&1 &
DAEMON_PID=$!

# Wait up to ~8s for the safe-mode banner (programs loaded) or an early crash.
for _ in $(seq 1 40); do
  if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
    warn "daemon exited early. Its log (paste this back to Claude):"
    echo "------------------------------------------------------------------"
    cat "$LOG" || true
    echo "------------------------------------------------------------------"
    die "daemon did not stay up — most likely the BPF verifier rejected the program."
  fi
  grep -q "safe-mode" "$LOG" 2>/dev/null && break
  sleep 0.2
done
if grep -qiE "verifier|failed to load|BPF program load|invalid|rejected" "$LOG"; then
  warn "possible load/verifier errors found. Full log (paste this back to Claude):"
  echo "------------------------------------------------------------------"
  cat "$LOG"
  echo "------------------------------------------------------------------"
  die "kernel rejected the program; the dentry-walk needs a verifier fix."
fi
ok "daemon is up in safe mode (it will not block anything)."

say "Step 6/7 — create a deeply nested file and watch what Jinn Guard records"
rm -f "$TEST_FILE" 2>/dev/null || true
mkdir -p "$TEST_DIR"
# Two operations the inode hooks see: create, then delete.
: > "$TEST_FILE"
sleep 0.4
rm -f "$TEST_FILE"
sleep 0.4
ok "created and deleted $TEST_FILE"

say "Step 7/7 — result"
if grep -qF "$EXPECTED_PATH" "$LOG"; then
  ok "Jinn Guard recorded the FULL path: $EXPECTED_PATH"
  printf '\n\033[1;32m############################################################\n'
  printf '#  M2 PASS — full-path resolution works. CVE-2026-002 fix   #\n'
  printf '#  is behaving correctly in audit-only mode.                #\n'
  printf '############################################################\033[0m\n'
  echo
  echo "Relevant log lines:"
  grep -F "$EXPECTED_PATH" "$LOG" | head -8
else
  warn "did not find the full path in the log. What we DID see for our test file:"
  echo "------------------------------------------------------------------"
  grep -iE "secret.txt|jinnguard-test|inode" "$LOG" | head -20 || echo "(no related lines)"
  echo "------------------------------------------------------------------"
  echo "Full log is at: $LOG"
  die "full path not confirmed — copy the lines above back to Claude to diagnose."
fi
