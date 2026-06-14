#!/usr/bin/env bash
#
# scripts/demo.sh — One-command live Jinn Guard demo for stakeholders.
#
# Builds the real daemon (if needed) and runs an interactive, narrated
# dashboard that drives the ACTUAL product: one legitimate request is allowed,
# seven real attacks are blocked live, the daemon's own metrics are read back,
# and the validated benchmark "receipts" + safety guarantees are walked through.
#
# Nothing is mocked. It governs only a private throwaway agent, binds metrics to
# loopback, and cleans up everything on exit. It cannot touch your machine or
# lock you out.
#
# Usage:
#   bash scripts/demo.sh           # interactive (press ENTER to advance)
#   bash scripts/demo.sh --auto    # autoplay (good for screen recording)
#   bash scripts/demo.sh --help    # passthrough flags to the dashboard
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

c_info() { printf '\033[2m%s\033[0m\n' "$*"; }
c_ok()   { printf '\033[1;32m%s\033[0m\n' "$*"; }

# 1. Make sure the real binary exists. Prefer release (the benchmarked build);
#    fall back to debug if a release build isn't present and can't be made.
if [[ ! -x target/release/ts_cli && ! -x target/debug/ts_cli ]]; then
  c_info "Building the Jinn Guard daemon (first run only, ~1-2 min)..."
  if ! cargo build --release -p ts_cli 2>/dev/null; then
    c_info "Release build unavailable; building debug..."
    cargo build -p ts_cli
  fi
fi

if [[ -x target/release/ts_cli ]]; then
  c_ok "Using release build: target/release/ts_cli"
else
  c_ok "Using debug build: target/debug/ts_cli"
fi

# 2. Find a Python 3.
PY="$(command -v python3 || command -v python || true)"
if [[ -z "$PY" ]]; then
  echo "ERROR: python3 is required to run the demo dashboard." >&2
  exit 1
fi

# 3. Run the dashboard (passes through any flags, e.g. --auto).
exec "$PY" scripts/demo/jinn_guard_demo.py "$@"
