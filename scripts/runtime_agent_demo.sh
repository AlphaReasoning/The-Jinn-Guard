#!/usr/bin/env bash
set -euo pipefail

export JINN_GUARD_SECRET="${JINN_GUARD_SECRET:-dev-only-change-me}"
export JINN_GUARD_SOCKET="${JINN_GUARD_SOCKET:-${JINNGUARD_SOCKET:-/run/jinnguard/jinnguard.sock}}"
export JINNGUARD_SOCKET="$JINN_GUARD_SOCKET"
export JINN_AGENT_ID="${JINN_AGENT_ID:-locked_agent_dev_01}"
export PYTHONPATH="$(pwd)/jinnguard_py${PYTHONPATH:+:${PYTHONPATH}}"
export PYTHONDONTWRITEBYTECODE=1

python3 examples/step2_mandatory_mediation_demo.py
