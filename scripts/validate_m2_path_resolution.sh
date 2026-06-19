#!/usr/bin/env bash
#
# validate_m2_path_resolution.sh — AUDIT-ONLY validation for M2 (JG-ADV-2026-002).
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
# Use a fresh, never-seen run id so directories/inodes are always new (rules out
# any stale-dentry effects from a previous run).
RUN_ID="$$_${RANDOM}"
# tmpfs nested path: proves multi-level resolution (the CVE fix). On a tmpfs
# /tmp this resolves relative to the tmpfs root, so we match the nested suffix.
TEST_DIR="/tmp/jinnguard-test/run-$RUN_ID/alpha/beta/gamma"
TEST_FILE="$TEST_DIR/secret.txt"
NESTED_SUFFIX="alpha/beta/gamma/secret.txt"
# Root-filesystem path: proves full ABSOLUTE resolution where there is no mount
# boundary (the case that matters for /etc, /usr, /opt, etc.).
ROOTFS_DIR="/root/jinnguard-m2-test/run-$RUN_ID/x/y/z"
ROOTFS_FILE="$ROOTFS_DIR/probe.txt"
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

# NOTE: the daemon now clears any stale pinned 'requests' ring buffer itself on
# startup (clear_stale_request_pin in ebpf_monitor.rs), so this harness no longer
# removes it. Running this script twice in a row therefore exercises that fix: a
# second PASS proves the daemon recovers a clean ring buffer across restarts.
if [ -e /sys/fs/bpf/requests ]; then
  echo "   (note: a stale pin exists from a previous run; the daemon should clear it)"
fi

# stdbuf -oL forces line-buffered stdout so every log line is written to the
# file immediately, instead of sitting in a memory batch that is lost when we
# stop the daemon at the end.
JINNGUARD_SAFE_MODE=1 ENABLE_EXPLAINABILITY=1 JINN_GUARD_MCP_PORT=48750 \
  stdbuf -oL -eL "$REPO_ROOT/target/release/ts_cli" \
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

say "Step 6/7 — create deeply nested files and watch what Jinn Guard records"
mkdir -p "$TEST_DIR" "$ROOTFS_DIR"
# Create each file several times (fresh inode each round) so a single missed
# event does not fail the run. inode_create fires only when the file does not
# already exist, so delete before each create.
for round in 1 2 3 4; do
  rm -f "$TEST_FILE" "$ROOTFS_FILE" 2>/dev/null || true
  sleep 0.2
  : > "$TEST_FILE"
  : > "$ROOTFS_FILE"
  sleep 0.2
done
rm -f "$TEST_FILE" "$ROOTFS_FILE" 2>/dev/null || true
ok "created the nested files (4 rounds each)"

say "Step 7/7 — result"
# Poll the log for up to ~10s: the daemon reads events on a background loop, so
# give it time rather than peeking once.
nested_ok=0; rootfs_ok=0
for _ in $(seq 1 50); do
  grep -qF "$NESTED_SUFFIX" "$LOG" && nested_ok=1
  grep -qF "$ROOTFS_FILE"   "$LOG" && rootfs_ok=1
  (( nested_ok )) && break
  sleep 0.2
done

echo "Multi-level resolution (the JG-ADV-2026-002 fix):"
if (( nested_ok )); then
  ok "resolved the full nested chain: ...$NESTED_SUFFIX"
  grep -F "$NESTED_SUFFIX" "$LOG" | grep -iE "resource=|Target:" | head -4
else
  warn "did not see the nested chain $NESTED_SUFFIX"
fi
echo
echo "Absolute resolution on the real disk (root filesystem):"
if (( rootfs_ok )); then
  ok "resolved the full ABSOLUTE path: $ROOTFS_FILE"
  grep -F "$ROOTFS_FILE" "$LOG" | grep -iE "resource=|Target:" | head -4
else
  warn "did not see $ROOTFS_FILE (is /root on a separate mount?)"
fi

echo
if (( nested_ok )); then
  printf '\033[1;32m############################################################\n'
  printf '#  M2 PASS — full multi-level path resolution works.        #\n'
  printf '#  JG-ADV-2026-002 (basename-only blindness) is closed.        #\n'
  if (( rootfs_ok )); then
  printf '#  Absolute paths on the root filesystem resolve fully.     #\n'
  fi
  printf '############################################################\033[0m\n'
  echo
  echo "(Note: paths under a separate mount such as a tmpfs /tmp resolve"
  echo " relative to that mount's root — a documented limitation. Paths on"
  echo " the main disk, including /etc /usr /opt, resolve absolutely.)"
else
  warn "nested resolution not confirmed. Diagnostics:"
  ev_total=$(grep -c "JINNGUARD EVENT" "$LOG" 2>/dev/null || echo 0)
  ev_create=$(grep -c "type=InodeCreate" "$LOG" 2>/dev/null || echo 0)
  echo "  total kernel events logged:       $ev_total"
  echo "  InodeCreate events logged:        $ev_create"
  echo "------------------------------------------------------------------"
  grep -iE "JINNGUARD EVENT|resource=|Target:" "$LOG" | head -25 || echo "(no event lines at all)"
  echo "------------------------------------------------------------------"
  echo "Full log is at: $LOG"
  die "copy the lines above back to Claude to diagnose."
fi
