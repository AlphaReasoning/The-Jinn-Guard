#!/usr/bin/env bash
#
# validate_m5_mandatory_mediation.sh — Step 3 / M5 Docker validation.
#
# WHAT THIS DOES, IN PLAIN WORDS:
#   It builds two containers and runs the mandatory-mediation test:
#     1. jinnguard-broker — runs the Jinn Guard daemon (userspace governance).
#     2. locked-agent     — a maximally restricted AI-agent sandbox: no network,
#                           read-only filesystem, ALL Linux capabilities dropped,
#                           no-new-privileges, a seccomp filter, and the ONLY
#                           thing it can reach is the Jinn Guard socket.
#   The locked agent then tries to misbehave and to behave. It must prove:
#     - it is de-privileged (non-root, no caps, network isolated)   [attestation]
#     - a direct network connection is BLOCKED
#     - a direct write to /etc is BLOCKED
#     - a direct shell command is BLOCKED
#     - a "just give me a verdict, I'll act myself" proposal is DENIED
#       (DENY_RUNTIME_POLICY — the agent is not allowed to self-execute)
#     - a broker-OWNED shell command SUCCEEDS (Jinn Guard runs it, not the agent)
#     - a broker-OWNED file write SUCCEEDS
#
# WHY IT IS SAFE:
#   Everything runs inside Docker containers. The daemon here uses the default
#   (userspace) build with NO kernel LSM enforcement, so nothing touches your
#   host's kernel or your desktop. It cannot lock you out.
#
# HOW TO RUN (from the repo root):
#   sudo bash scripts/validate_m5_mandatory_mediation.sh
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG="/tmp/jg-m5-validate.log"
COMPOSE_FILE="docker-compose.runtime.yml"

say()  { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m   OK: %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m   ! %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31m   FAIL: %s\033[0m\n' "$*" >&2; exit 1; }

cd "$REPO_ROOT"

say "Step 1/4 — checks"
command -v docker >/dev/null 2>&1 || die "docker is not installed. Install Docker Engine first: https://docs.docker.com/engine/install/debian/"
if docker compose version >/dev/null 2>&1; then
  DC="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
  DC="docker-compose"
else
  die "docker compose plugin not found. Install: apt-get install docker-compose-plugin"
fi
docker info >/dev/null 2>&1 || die "the Docker daemon is not running or not reachable. Start it: systemctl start docker"
ok "docker present ($DC), daemon reachable"

# Belt-and-suspenders: ensure no stale runtime containers/volumes linger.
$DC -f "$COMPOSE_FILE" down -v --remove-orphans >/dev/null 2>&1 || true

say "Step 2/4 — build broker + locked-agent images (first build compiles Rust; can take a few minutes)"
if ! $DC -f "$COMPOSE_FILE" build jinnguard-broker locked-agent 2>&1 | tee "$LOG" | tail -1; then
  die "image build failed; see $LOG"
fi
ok "images built"

say "Step 3/4 — run the locked agent against the broker"
# Bring up BOTH services attached so broker logs are visible, and use the
# locked-agent's exit code as the probe result (0 = all probes passed).
set +e
$DC -f "$COMPOSE_FILE" up --abort-on-container-exit --exit-code-from locked-agent 2>&1 | tee -a "$LOG"
rc=${PIPESTATUS[0]}
# Capture the broker's own logs explicitly in case it died before the agent ran.
{ echo "----- jinnguard-broker logs -----"; $DC -f "$COMPOSE_FILE" logs jinnguard-broker 2>&1 | tail -40; } >> "$LOG" 2>&1 || true
$DC -f "$COMPOSE_FILE" down -v --remove-orphans >/dev/null 2>&1 || true
set -e

say "Step 4/4 — result"
echo "Probe outcomes (from the locked agent):"
echo "------------------------------------------------------------------"
grep -E "^\[(PASS|FAIL)\] " "$LOG" | tail -20 || echo "(no probe lines captured)"
echo "------------------------------------------------------------------"

# Count expected probes.
expected=(runtime_attestation direct_network_egress direct_sensitive_file_write \
          direct_shell verdict_only_proposed_action broker_owned_shell_execution \
          broker_owned_file_write)
pass_count=0
for p in "${expected[@]}"; do
  if grep -qE "^\[PASS\] $p:" "$LOG"; then pass_count=$((pass_count+1)); fi
done

echo
if [[ "$rc" -eq 0 && "$pass_count" -eq "${#expected[@]}" ]]; then
  printf '\033[1;32m############################################################\n'
  printf '#  M5 PASS — mandatory mediation enforced.                  #\n'
  printf '#  The locked agent cannot act directly; only broker-owned  #\n'
  printf '#  actions through Jinn Guard succeed. %d/%d probes passed.   #\n' "$pass_count" "${#expected[@]}"
  printf '############################################################\033[0m\n'
else
  warn "mandatory-mediation validation did not fully pass ($pass_count/${#expected[@]} probes, exit=$rc)."
  echo "Full log: $LOG"
  echo "Paste the probe outcomes above (and any FAIL detail) back to Claude."
  exit 1
fi
