#!/usr/bin/env python3
"""Step 2 bypass probe for the mandatory mediation sandbox.

Expected result inside docker-compose.runtime.yml:
  - runtime attestation sees non-root, no caps, no-new-privileges, socket present
  - direct network egress fails
  - direct sensitive file write fails
  - direct shell execution via /bin/sh fails
  - verdict-only proposed_action is denied by runtime_policy
  - broker-owned shell and file write succeed through Jinn Guard
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "jinnguard_py"))

import jinnguard  # noqa: E402


AGENT_ID = (
    os.environ.get("JINN_AGENT_ID")
    or os.environ.get("JINNGUARD_AGENT_ID")
    or os.environ.get("JINN_GUARD_AGENT_ID")
    or "locked_agent_dev_01"
)
SOCKET_PATH = (
    os.environ.get("JINN_GUARD_SOCKET")
    or os.environ.get("JINNGUARD_SOCKET")
    or "/run/jinnguard/jinnguard.sock"
)


def wait_for_socket(path: str, timeout_seconds: float = 300.0) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if os.path.exists(path):
            return
        time.sleep(0.25)
    raise TimeoutError(f"Jinn Guard socket did not appear: {path}")


def record(results: list[dict], name: str, passed: bool, detail: str) -> None:
    row = {"probe": name, "passed": passed, "detail": detail}
    results.append(row)
    marker = "PASS" if passed else "FAIL"
    print(f"[{marker}] {name}: {detail}")


def probe_runtime_attestation(results: list[dict]) -> None:
    attestation = jinnguard.runtime_attestation(SOCKET_PATH)
    passed = (
        attestation.get("uid") != 0
        and attestation.get("euid") != 0
        and attestation.get("cap_eff") in (0, None)
        and attestation.get("cap_prm") in (0, None)
        and attestation.get("no_new_privs") is True
        and attestation.get("network_isolated") is True
        and attestation.get("socket_present") is True
    )
    record(results, "runtime_attestation", passed, json.dumps(attestation, sort_keys=True))


def probe_direct_network(results: list[dict]) -> None:
    try:
        with socket.create_connection(("93.184.216.34", 80), timeout=2.0):
            record(results, "direct_network_egress", False, "unexpected TCP connection succeeded")
    except OSError as exc:
        record(results, "direct_network_egress", True, f"blocked: {exc.__class__.__name__}: {exc}")


def probe_direct_sensitive_write(results: list[dict]) -> None:
    target = "/etc/jinnguard-bypass-probe"
    try:
        with open(target, "w", encoding="utf-8") as handle:
            handle.write("bypass\n")
        try:
            os.remove(target)
        except OSError:
            pass
        record(results, "direct_sensitive_file_write", False, f"unexpected write succeeded: {target}")
    except OSError as exc:
        record(results, "direct_sensitive_file_write", True, f"blocked: {exc.__class__.__name__}: {exc}")


def probe_direct_shell(results: list[dict]) -> None:
    try:
        completed = subprocess.run(
            "printf bypass-shell",
            shell=True,
            text=True,
            capture_output=True,
            timeout=3.0,
            check=False,
        )
        if completed.returncode == 0:
            record(results, "direct_shell", False, f"unexpected shell output: {completed.stdout!r}")
        else:
            detail = (completed.stderr or completed.stdout or f"exit={completed.returncode}").strip()
            record(results, "direct_shell", True, f"blocked/nonzero: {detail}")
    except (OSError, subprocess.SubprocessError) as exc:
        record(results, "direct_shell", True, f"blocked: {exc.__class__.__name__}: {exc}")


def probe_verdict_only_denied(results: list[dict]) -> None:
    client = jinnguard.JinnGuardClient()
    sequence = int(time.time() * 1000) % 10_000_000
    response = client.send_proposal(
        {
            "agent_id": AGENT_ID,
            "intent_name": "write_file",
            "sequence_counter": sequence,
            "action_risk_score": 5.0,
            "context_vars": {
                "spending_ceiling_usd": 0.0,
                "privilege_escalation_depth": 0.0,
            },
            "proposed_action": {
                "kind": "file_write",
                "path": "/tmp/verdict_only_should_not_write.txt",
                "contents": "nope\n",
            },
        },
        execute=False,
    )
    passed = "DENY_RUNTIME_POLICY" in response
    record(results, "verdict_only_proposed_action", passed, response.strip())


def probe_broker_shell_execution(results: list[dict]) -> None:
    with jinnguard.Guard(agent_id=AGENT_ID) as guard:
        verdict = guard.execute_shell(
            "printf brokered-step2-ok",
            risk_score=5.0,
            intent_name="execute_shell",
        )
    result = verdict.get_result() or {}
    passed = (
        verdict.is_allowed()
        and result.get("executed") is True
        and result.get("stdout") == "brokered-step2-ok"
    )
    record(results, "broker_owned_shell_execution", passed, verdict.response.strip())


def probe_broker_file_write(results: list[dict]) -> None:
    with jinnguard.Guard(agent_id=AGENT_ID) as guard:
        verdict = guard.write_file(
            "/tmp/jinn_guard_step2_broker.txt",
            "written by the broker, not by the agent sandbox\n",
            risk_score=5.0,
            intent_name="write_file",
        )
    result = verdict.get_result() or {}
    passed = verdict.is_allowed() and result.get("executed") is True
    record(results, "broker_owned_file_write", passed, verdict.response.strip())


def main() -> int:
    wait_for_socket(SOCKET_PATH)
    results: list[dict] = []

    probe_runtime_attestation(results)
    probe_direct_network(results)
    probe_direct_sensitive_write(results)
    probe_direct_shell(results)
    probe_verdict_only_denied(results)
    probe_broker_shell_execution(results)
    probe_broker_file_write(results)

    print("\nJSON summary:")
    print(json.dumps(results, indent=2))
    return 0 if all(item["passed"] for item in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
