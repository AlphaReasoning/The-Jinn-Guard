#!/usr/bin/env bash
set -euo pipefail

export JINN_GUARD_SECRET="${JINN_GUARD_SECRET:-dev-only-change-me}"
export JINN_GUARD_SOCKET="${JINN_GUARD_SOCKET:-${JINNGUARD_SOCKET:-/tmp/jinnguard.sock}}"
export JINNGUARD_SOCKET="${JINN_GUARD_SOCKET}"
mkdir -p "$(dirname "$JINN_GUARD_SOCKET")"
export JINN_GUARD_AUDIT="${JINN_GUARD_AUDIT:-/tmp/jinnguard-audit.log}"
export JINN_GUARD_LINEAGE="${JINN_GUARD_LINEAGE:-/tmp/jinnguard-lineage.json}"
export JINN_GUARD_MCP_PORT="${JINN_GUARD_MCP_PORT:-4850}"
export PYTHONPATH="$(pwd)/jinnguard_py${PYTHONPATH:+:${PYTHONPATH}}"
LOG_FILE="${JINN_GUARD_DAEMON_LOG:-/tmp/jinnguard-sandbox-daemon.log}"

rm -f "$JINN_GUARD_SOCKET" "$JINN_GUARD_AUDIT" "$JINN_GUARD_AUDIT.db" "$JINN_GUARD_LINEAGE" "$LOG_FILE"

cargo build --workspace --locked

cargo run --locked -p ts_cli -- \
  --socket-path "$JINN_GUARD_SOCKET" \
  --policy-file ./policy.yaml \
  --lineage-file "$JINN_GUARD_LINEAGE" \
  --audit-log "$JINN_GUARD_AUDIT" \
  --mcp-port "$JINN_GUARD_MCP_PORT" \
  --allow-anonymous \
  >"$LOG_FILE" 2>&1 &
DAEMON_PID="$!"

cleanup() {
  kill "$DAEMON_PID" >/dev/null 2>&1 || true
  wait "$DAEMON_PID" >/dev/null 2>&1 || true
  rm -f "$JINN_GUARD_SOCKET"
}
trap cleanup EXIT

for _ in $(seq 1 120); do
  if [[ -S "$JINN_GUARD_SOCKET" ]]; then
    break
  fi
  if ! kill -0 "$DAEMON_PID" >/dev/null 2>&1; then
    echo "Jinn Guard daemon exited before binding $JINN_GUARD_SOCKET. Log follows:" >&2
    cat "$LOG_FILE" >&2 || true
    exit 1
  fi
  sleep 0.25
done

if [[ ! -S "$JINN_GUARD_SOCKET" ]]; then
  echo "Jinn Guard daemon did not create socket: $JINN_GUARD_SOCKET. Log follows:" >&2
  cat "$LOG_FILE" >&2 || true
  exit 1
fi

python3 examples/step1_capability_broker_demo.py
