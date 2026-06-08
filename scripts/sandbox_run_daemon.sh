#!/usr/bin/env bash
set -euo pipefail

export JINN_GUARD_SECRET="${JINN_GUARD_SECRET:-dev-only-change-me}"
export JINN_GUARD_SOCKET="${JINN_GUARD_SOCKET:-${JINNGUARD_SOCKET:-/tmp/jinnguard.sock}}"
export JINNGUARD_SOCKET="${JINN_GUARD_SOCKET}"
mkdir -p "$(dirname "$JINN_GUARD_SOCKET")"
export JINN_GUARD_AUDIT="${JINN_GUARD_AUDIT:-/tmp/jinnguard-audit.log}"
export JINN_GUARD_LINEAGE="${JINN_GUARD_LINEAGE:-/tmp/jinnguard-lineage.json}"
export JINN_GUARD_MCP_PORT="${JINN_GUARD_MCP_PORT:-4850}"

rm -f "$JINN_GUARD_SOCKET"

cargo run --locked -p ts_cli -- \
  --socket-path "$JINN_GUARD_SOCKET" \
  --policy-file ./policy.yaml \
  --lineage-file "$JINN_GUARD_LINEAGE" \
  --audit-log "$JINN_GUARD_AUDIT" \
  --mcp-port "$JINN_GUARD_MCP_PORT" \
  --allow-anonymous
