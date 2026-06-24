#!/usr/bin/env python3
"""Validate that verify_audit_chain.py surfaces boot-marker provenance."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from verify_audit_chain import recompute_hash, verify


def make_entry() -> str:
    entry = {
        "index": 0,
        "timestamp_secs": 123,
        "prev_hash": "0" * 64,
        "observation": {
            "pid": 1,
            "start_time": 1,
            "namespace_observed": True,
            "namespace_pid_inode": None,
            "namespace_net_inode": None,
            "socket_peer_verified": True,
            "observed_at_unix_secs": 123,
            "subject_pseudonym": "subject",
            "pii_ref": "pii",
            "pii_commitment": "commitment",
        },
        "intent": {
            "class": "Boot",
            "confidence": 1.0,
            "risk_score": 0.0,
            "signals": [
                "jinnguard.boot_marker",
                "ostree_booted=true",
                "ostree_commit=abc123",
                "kernel_release=6.17.0-test",
            ],
        },
        "assessment": {
            "observed_risk": 0.0,
            "semantic_risk": 0.0,
            "topology_risk": 0.0,
            "declared_risk": None,
            "fused_risk": 0.0,
            "trust_score": 100.0,
            "reasons": ["boot_marker"],
        },
        "decision": {
            "verdict": "Allow",
            "reason": "boot_marker",
            "risk_score": 0.0,
            "trust_score": 100.0,
        },
        "hash": "",
    }
    raw = json.dumps(entry, separators=(",", ":"))
    entry["hash"] = recompute_hash(
        raw, entry["index"], entry["timestamp_secs"], entry["prev_hash"]
    )
    return json.dumps(entry, separators=(",", ":"))


def main() -> None:
    with tempfile.TemporaryDirectory() as raw:
        path = Path(raw) / "audit.log"
        path.write_text(make_entry() + "\n", encoding="utf-8")
        ok, msg, entries = verify(str(path))
        assert ok, msg
        assert entries == 1
        assert "ostree_commit=abc123" in msg
        assert "kernel_release=6.17.0-test" in msg
        assert "ostree_booted=true" in msg
        print("ok - verify_audit_chain surfaces boot-marker provenance")


if __name__ == "__main__":
    main()
