#!/usr/bin/env bash
set -euo pipefail

export JINN_GUARD_SECRET="${JINN_GUARD_SECRET:-dev-only-change-me}"
export JINN_GUARD_SOCKET="${JINN_GUARD_SOCKET:-${JINNGUARD_SOCKET:-/tmp/jinnguard.sock}}"
export JINNGUARD_SOCKET="${JINN_GUARD_SOCKET}"
export PYTHONPATH="$(pwd)/jinnguard_py${PYTHONPATH:+:${PYTHONPATH}}"

python3 examples/step1_capability_broker_demo.py
