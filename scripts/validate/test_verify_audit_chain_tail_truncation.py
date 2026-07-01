#!/usr/bin/env python3
"""JG-RT-031 regression: verify_audit_chain.py must detect tail-truncation.

A pure hash chain cannot prove its own end is complete — an attacker who deletes
the last K entries (e.g. the records of their own actions) leaves a still-valid
shorter prefix. The validator must catch this via any available tail anchor
(--expected-head, --min-entries, or the signed <log>.manifests sidecar) and must
warn loudly when no anchor is available.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from verify_audit_chain import recompute_hash, verify, GENESIS


def make_chain(n):
    """Build an internally-valid n-entry chain; return (lines, hashes)."""
    lines = []
    hashes = []
    prev = GENESIS
    for i in range(n):
        entry = {
            "index": i,
            "timestamp_secs": 1000 + i,
            "prev_hash": prev,
            "observation": {"pid": 100 + i, "subject_pseudonym": "s", "note": "e%d" % i},
            "intent": {"class": "Exec", "signals": []},
            "assessment": {"fused_risk": 0.1, "trust_score": 0.9},
            "decision": {"verdict": "Allow", "reason": "e%d" % i},
        }
        raw = json.dumps(entry, separators=(",", ":"))
        h = recompute_hash(raw, i, entry["timestamp_secs"], prev)
        entry["hash"] = h
        lines.append(json.dumps(entry, separators=(",", ":")))
        hashes.append(h)
        prev = h
    return lines, hashes


def make_manifests(hashes):
    """Minimal signed-manifest sidecar: one action record per entry index."""
    out = []
    for i, h in enumerate(hashes):
        out.append(json.dumps({
            "type": "action",
            "manifest": {"schema": "jinnguard/action@0", "index": i,
                         "entry_hash": h},
            "sig": "x" * 8,
        }, separators=(",", ":")))
    return "\n".join(out) + "\n"


def main():
    with tempfile.TemporaryDirectory() as raw:
        d = Path(raw)
        lines, hashes = make_chain(4)
        full = d / "audit.log"
        full.write_text("\n".join(lines) + "\n", encoding="utf-8")

        # (1) No anchor: still ok, but message must WARN about tail-truncation.
        ok, msg, n = verify(str(full))
        assert ok and n == 4, msg
        assert "no tail anchor" in msg.lower(), \
            "unanchored verify must warn about tail-truncation risk: %s" % msg

        # (2) --expected-head anchors the tail: truncation is caught.
        truncated = d / "audit_trunc.log"
        truncated.write_text("\n".join(lines[:3]) + "\n", encoding="utf-8")
        ok, msg, n = verify(str(truncated), expected_head=hashes[-1])
        assert not ok and "TAIL TRUNCATED" in msg, \
            "expected-head must catch tail-truncation: %s" % msg

        # Full chain WITH the correct head verifies.
        ok, msg, n = verify(str(full), expected_head=hashes[-1])
        assert ok, msg

        # (3) --min-entries catches a short chain.
        ok, msg, n = verify(str(truncated), min_entries=4)
        assert not ok and "TAIL TRUNCATED" in msg, msg

        # (4) Signed .manifests sidecar catches truncation automatically.
        (d / "audit_trunc.log.manifests").write_text(
            make_manifests(hashes), encoding="utf-8")
        ok, msg, n = verify(str(truncated))
        assert not ok and "TAIL TRUNCATED" in msg and "signed manifest" in msg, \
            "manifest sidecar must catch tail-truncation: %s" % msg

        # Sidecar matching the full chain verifies clean (and is anchored, no warn).
        (d / "audit.log.manifests").write_text(
            make_manifests(hashes), encoding="utf-8")
        ok, msg, n = verify(str(full))
        assert ok and "no tail anchor" not in msg.lower(), msg

        print("ok - verify_audit_chain detects tail-truncation via all three anchors")


if __name__ == "__main__":
    main()
