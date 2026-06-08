#!/usr/bin/env python3
"""Step 1 capability-broker demo for local sandbox runs.

Prereqs:
  export JINN_GUARD_SECRET='dev-secret'
  cargo run -p ts_cli -- \
    --socket-path "${JINN_GUARD_SOCKET:-/tmp/jinnguard.sock}" \
    --policy-file ./policy.yaml \
    --lineage-file /tmp/jg-lineage.json \
    --audit-log /tmp/jg-audit.log \
    --allow-anonymous
"""

import os

import jinnguard


def show(label, response):
    print(f"\n== {label} ==")
    print(response)


if __name__ == "__main__":
    os.environ.setdefault("JINN_GUARD_SECRET", "dev-secret")
    socket_path = (
        os.environ.get("JINN_GUARD_SOCKET")
        or os.environ.get("JINNGUARD_SOCKET")
        or "/tmp/jinnguard.sock"
    )
    with jinnguard.Guard(socket_path=socket_path) as guard:
        show("low-risk audit", guard.audit(privilege=0.0, risk_score=10.0, intent_name="agent_action"))
        show("risk-ceiling denial", guard.audit(privilege=0.0, risk_score=96.0, intent_name="agent_action"))
