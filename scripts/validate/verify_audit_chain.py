#!/usr/bin/env python3
"""
verify_audit_chain.py — independently verify the Jinn Guard tamper-evident audit log.

Standard library only. No daemon required. This recomputes the SHA-256 hash chain
*exactly* as the daemon does and checks every link, so you do not have to trust the
daemon's own word that the log is intact — you can prove it yourself.

Hash construction (mirrors ts_cli/src/governance.rs::AuditEntry::calculate_hash):

    entry_hash = SHA256(
          index            as 8-byte big-endian
        + timestamp_secs   as 8-byte big-endian
        + prev_hash        (utf-8 bytes of the hex string)
        + observation_json (the exact serialized bytes, taken from the log line)
        + intent_json
        + assessment_json
        + decision_json
    )  ->  lowercase hex

Crucial detail: the four sub-object JSON strings are extracted *verbatim* from the
raw log line by brace-matching, NOT re-serialized. That makes verification exact
and float-safe — a re-serializer in another language could format a float
differently and produce false tamper alarms. We compare the daemon's own bytes.

Checks, per entry:
  1. index increments by 1 from 0          (no insert/delete/reorder)
  2. prev_hash == previous entry's hash     (chain linkage)
  3. recomputed hash == stored hash         (content binding)

Exit 0 = verified, 1 = tamper detected, 2 = usage/empty.

Usage:  python3 verify_audit_chain.py <audit.log>
"""
import hashlib
import json
import struct
import sys

GENESIS = "0" * 64


def _extract_object(line, key, start):
    """Return (raw_substring, end_index) for "<key>":{...}, brace-matched and
    string/escape aware, searching at or after `start`. Gives the exact bytes the
    daemon serialized for that sub-object."""
    marker = '"%s":' % key
    i = line.find(marker, start)
    if i < 0:
        raise ValueError("missing top-level key %r" % key)
    j = i + len(marker)
    if j >= len(line) or line[j] != "{":
        raise ValueError("value for %r is not an object" % key)
    depth = 0
    in_str = False
    esc = False
    k = j
    while k < len(line):
        c = line[k]
        if in_str:
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
        elif c == '"':
            in_str = True
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return line[j:k + 1], k + 1
        k += 1
    raise ValueError("unterminated object for %r" % key)


def recompute_hash(line, index, timestamp_secs, prev_hash):
    h = hashlib.sha256()
    h.update(struct.pack(">Q", index))
    h.update(struct.pack(">Q", timestamp_secs))
    h.update(prev_hash.encode("utf-8"))
    cursor = 0
    for key in ("observation", "intent", "assessment", "decision"):
        raw, cursor = _extract_object(line, key, cursor)
        h.update(raw.encode("utf-8"))
    return h.hexdigest()


def verify(path):
    """Return (ok: bool, message: str, n_entries: int)."""
    with open(path, encoding="utf-8") as f:
        lines = [ln for ln in f.read().splitlines() if ln.strip()]
    if not lines:
        return False, "audit log is empty: %s" % path, 0

    prev = GENESIS
    expected_index = 0
    for n, line in enumerate(lines):
        try:
            entry = json.loads(line)
        except json.JSONDecodeError as e:
            return False, "line %d is not valid JSON: %s" % (n + 1, e), n

        idx = entry.get("index")
        ts = entry.get("timestamp_secs")
        stored_prev = entry.get("prev_hash")
        stored_hash = entry.get("hash")

        if idx != expected_index:
            return (False,
                    "line %d: index gap (expected %d, got %r) — insert/delete/reorder"
                    % (n + 1, expected_index, idx), n)
        if stored_prev != prev:
            return (False,
                    "line %d (index %d): broken link — prev_hash does not match the "
                    "previous entry's hash (reorder/insert/delete)" % (n + 1, idx), n)
        try:
            calc = recompute_hash(line, idx, ts, stored_prev)
        except ValueError as e:
            return False, "line %d (index %d): malformed entry — %s" % (n + 1, idx, e), n
        if calc != stored_hash:
            return (False,
                    "line %d (index %d): CONTENT TAMPERED — recomputed hash %s… != "
                    "stored hash %s…" % (n + 1, idx, calc[:12], str(stored_hash)[:12]), n)

        prev = stored_hash
        expected_index += 1

    return True, "%d entries — links intact, every content hash matches" % len(lines), len(lines)


def main(argv):
    if len(argv) != 2:
        print("usage: python3 verify_audit_chain.py <audit.log>")
        return 2
    ok, msg, _ = verify(argv[1])
    if ok:
        print("AUDIT CHAIN VERIFIED  ✓  " + msg)
        return 0
    print("AUDIT CHAIN FAILED  ✗  " + msg)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
