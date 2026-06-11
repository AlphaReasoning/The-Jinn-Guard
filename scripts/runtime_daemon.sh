#!/usr/bin/env bash
set -euo pipefail

# The Rust container exposes cargo under /usr/local/cargo/bin, but `sudo` resets
# PATH to its secure_path, dropping that directory, so `cargo` would not be found
# (exit 127). Re-add the cargo bin dir before invoking it.
export PATH="/usr/local/cargo/bin:${CARGO_HOME:-/usr/local/cargo}/bin:${PATH}"

export JINN_GUARD_SECRET="${JINN_GUARD_SECRET:-dev-only-change-me}"
export JINN_GUARD_SOCKET="${JINN_GUARD_SOCKET:-${JINNGUARD_SOCKET:-/run/jinnguard/jinnguard.sock}}"
export JINNGUARD_SOCKET="$JINN_GUARD_SOCKET"
export JINN_GUARD_POLICY="${JINN_GUARD_POLICY:-./policy.step2.yaml}"
export JINN_GUARD_AUDIT="${JINN_GUARD_AUDIT:-/tmp/jinnguard-runtime-audit.log}"
export JINN_GUARD_LINEAGE="${JINN_GUARD_LINEAGE:-/tmp/jinnguard-runtime-lineage.json}"
export JINN_GUARD_SOCKET_MODE="${JINN_GUARD_SOCKET_MODE:-0770}"
export JINN_GUARD_MCP_PORT="${JINN_GUARD_MCP_PORT:-4860}"

mkdir -p "$(dirname "$JINN_GUARD_SOCKET")" "$(dirname "$JINN_GUARD_AUDIT")" "$(dirname "$JINN_GUARD_LINEAGE")"
rm -f "$JINN_GUARD_SOCKET"

# Create the socket group-readable/writable for the agent sandbox group. The
# runtime compose profile keeps the directory non-writable for the agent, so it
# can connect to the socket but cannot delete or replace it.
umask 0007

cargo run --locked -p ts_cli -- \
  --socket-path "$JINN_GUARD_SOCKET" \
  --socket-mode "$JINN_GUARD_SOCKET_MODE" \
  --policy-file "$JINN_GUARD_POLICY" \
  --lineage-file "$JINN_GUARD_LINEAGE" \
  --audit-log "$JINN_GUARD_AUDIT" \
  --mcp-port "$JINN_GUARD_MCP_PORT"
