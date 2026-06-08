"""Runtime sandbox self-checks for locked-down Jinn Guard agents.

These checks are not the security boundary. Docker/Linux policy is the boundary.
They give demos and CI a cheap way to prove the agent process is non-root,
capability-free, running with no-new-privileges, and able to see the broker socket.
"""

from __future__ import annotations

import os
import socket
from pathlib import Path


_DEFAULT_ALLOWED_INTERFACES = {"lo"}


def _status_value(name: str) -> str | None:
    try:
        for line in Path("/proc/self/status").read_text().splitlines():
            if line.startswith(f"{name}:"):
                return line.split(":", 1)[1].strip()
    except OSError:
        return None
    return None


def _capability_mask(name: str) -> int | None:
    value = _status_value(name)
    if value is None:
        return None
    try:
        return int(value, 16)
    except ValueError:
        return None


def network_interfaces() -> list[str]:
    try:
        lines = Path("/proc/net/dev").read_text().splitlines()[2:]
    except OSError:
        return []
    interfaces = []
    for line in lines:
        if ":" in line:
            interfaces.append(line.split(":", 1)[0].strip())
    return sorted(interfaces)


def runtime_attestation(socket_path: str | None = None) -> dict:
    socket_path = (
        socket_path
        or os.environ.get("JINN_GUARD_SOCKET")
        or os.environ.get("JINNGUARD_SOCKET")
        or "/tmp/jinnguard.sock"
    )
    interfaces = network_interfaces()
    return {
        "uid": os.getuid(),
        "gid": os.getgid(),
        "euid": os.geteuid(),
        "egid": os.getegid(),
        "cap_eff": _capability_mask("CapEff"),
        "cap_prm": _capability_mask("CapPrm"),
        "no_new_privs": _status_value("NoNewPrivs") == "1",
        "network_interfaces": interfaces,
        "network_isolated": all(iface in _DEFAULT_ALLOWED_INTERFACES for iface in interfaces),
        "socket_path": socket_path,
        "socket_present": Path(socket_path).exists(),
    }


def assert_locked_runtime(socket_path: str | None = None) -> dict:
    """Raise RuntimeError unless the current process looks capability-deprived."""
    attestation = runtime_attestation(socket_path=socket_path)
    failures = []

    if attestation["uid"] == 0 or attestation["euid"] == 0:
        failures.append("process is running as root")
    if attestation["cap_eff"] not in (0, None):
        failures.append(f"effective capabilities are not empty: {attestation['cap_eff']:#x}")
    if attestation["cap_prm"] not in (0, None):
        failures.append(f"permitted capabilities are not empty: {attestation['cap_prm']:#x}")
    if not attestation["no_new_privs"]:
        failures.append("NoNewPrivs is not enabled")
    if not attestation["network_isolated"]:
        failures.append(f"unexpected network interfaces: {attestation['network_interfaces']}")
    if not attestation["socket_present"]:
        failures.append(f"broker socket is missing: {attestation['socket_path']}")

    if failures:
        raise RuntimeError("locked runtime attestation failed: " + "; ".join(failures))
    return attestation


def direct_network_probe(host: str = "93.184.216.34", port: int = 80, timeout: float = 2.0) -> dict:
    """Try a raw outbound TCP connect. In the locked runtime this should fail."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
    except OSError as exc:
        return {"connected": False, "error": str(exc)}
    finally:
        sock.close()
    return {"connected": True, "error": None}
