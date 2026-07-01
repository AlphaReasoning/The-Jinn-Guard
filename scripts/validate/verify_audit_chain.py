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

A pure hash chain proves internal consistency + genesis-anchoring, but it cannot
prove its own tail is complete — deleting the last K entries leaves a valid
shorter prefix. Tail-truncation is detected via (in order) an explicit
--expected-head / --min-entries anchor, or a co-located signed <log>.manifests
sidecar (#62); absent any anchor the result carries an explicit warning.

Exit 0 = verified, 1 = tamper detected, 2 = usage/empty.

Usage:  python3 verify_audit_chain.py <audit.log> \
            [--expected-head <hash>] [--min-entries <n>]
"""
import hashlib
import json
import os
import struct
import sys

GENESIS = "0" * 64
BOOT_MARKER_SIGNAL = "jinnguard.boot_marker"


def signed_high_water(path):
    """Highest entry index attested by the signed manifest sidecar
    (`<path>.manifests`), or None if there is no sidecar / it is unreadable.

    This is the tail anchor a bare hash chain lacks: an append-only chain proves
    internal consistency and genesis-anchoring, but nothing binds its *end*, so
    deleting the last K entries leaves a still-valid shorter prefix. The #62
    Action Manifest signs each entry index (and checkpoints sign a
    `[first,last]` range), so the maximum signed index is the lowest the real
    tail can be. We read the count here with the stdlib; verifying the Ed25519
    signatures themselves is the job of `ts_cli manifest verify` (see caveat)."""
    manifests = path + ".manifests"
    if not os.path.exists(manifests):
        return None
    high = None
    try:
        with open(manifests, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                idx = None
                if "manifest" in rec and isinstance(rec["manifest"], dict):
                    idx = rec["manifest"].get("index")
                elif "checkpoint" in rec and isinstance(rec["checkpoint"], dict):
                    idx = rec["checkpoint"].get("last_index")
                if isinstance(idx, int):
                    high = idx if high is None else max(high, idx)
    except (OSError, ValueError):
        return None
    return high


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


def _boot_marker_from_entry(entry):
    """Return boot-marker provenance if this entry carries it."""
    intent = entry.get("intent") or {}
    signals = intent.get("signals") or []
    if intent.get("class") != "Boot" and BOOT_MARKER_SIGNAL not in signals:
        return None

    provenance = {}
    for signal in signals:
        if not isinstance(signal, str) or "=" not in signal:
            continue
        key, value = signal.split("=", 1)
        provenance[key] = value
    return {
        "ostree_booted": provenance.get("ostree_booted", "unknown"),
        "ostree_commit": provenance.get("ostree_commit", "unknown"),
        "kernel_release": provenance.get("kernel_release", "unknown"),
    }


def verify(path, expected_head=None, min_entries=None):
    """Return (ok: bool, message: str, n_entries: int).

    `expected_head` / `min_entries` are optional out-of-band tail anchors: if you
    know the true final entry hash or minimum entry count from a trusted source,
    pass it and tail-truncation is detected. Absent an anchor, a co-located signed
    `<path>.manifests` sidecar is used to detect truncation automatically."""
    with open(path, encoding="utf-8") as f:
        lines = [ln for ln in f.read().splitlines() if ln.strip()]
    if not lines:
        return False, "audit log is empty: %s" % path, 0

    prev = GENESIS
    expected_index = 0
    boot_marker = None
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
        if boot_marker is None:
            boot_marker = _boot_marker_from_entry(entry)

    # ── Tail anchoring (JG-RT-031) ─────────────────────────────────────────────
    # The loop above proves the chain is internally consistent and genesis-
    # anchored, but a pure hash chain cannot prove its own *end* is complete:
    # deleting the last K entries leaves a still-valid shorter prefix. Detect
    # that with any available tail anchor.
    final_hash = prev
    highest_index = expected_index - 1
    anchored = False

    if expected_head is not None:
        anchored = True
        if final_hash != expected_head:
            return (False,
                    "TAIL TRUNCATED/ALTERED — final hash %s… != expected head %s… "
                    "(entries may have been removed from the end)"
                    % (final_hash[:12], str(expected_head)[:12]), len(lines))

    if min_entries is not None:
        anchored = True
        if len(lines) < min_entries:
            return (False,
                    "TAIL TRUNCATED — %d entries present, at least %d expected "
                    "(entries removed from the end)" % (len(lines), min_entries),
                    len(lines))

    signed_high = signed_high_water(path)
    if signed_high is not None:
        anchored = True
        if highest_index < signed_high:
            return (False,
                    "TAIL TRUNCATED — chain ends at index %d but the signed manifest "
                    "attests to index %d (%d entries removed from the end). Run "
                    "`ts_cli manifest verify` for the authoritative signature check."
                    % (highest_index, signed_high, signed_high - highest_index),
                    len(lines))

    msg = "%d entries — links intact, every content hash matches" % len(lines)
    if not anchored:
        msg += (
            " — WARNING: no tail anchor available, so truncation of the most recent "
            "entries CANNOT be ruled out by the chain alone. Pass --expected-head / "
            "--min-entries, ship the signed <log>.manifests sidecar, or run "
            "`ts_cli manifest verify`"
        )
    if boot_marker:
        msg += (
            " — boot marker: ostree_commit=%s kernel_release=%s ostree_booted=%s"
            % (
                boot_marker["ostree_commit"],
                boot_marker["kernel_release"],
                boot_marker["ostree_booted"],
            )
        )
    else:
        msg += " — boot marker: not found"

    return True, msg, len(lines)


def main(argv):
    args = argv[1:]
    expected_head = None
    min_entries = None
    positional = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--expected-head" and i + 1 < len(args):
            expected_head = args[i + 1]
            i += 2
        elif a == "--min-entries" and i + 1 < len(args):
            try:
                min_entries = int(args[i + 1])
            except ValueError:
                print("error: --min-entries expects an integer")
                return 2
            i += 2
        else:
            positional.append(a)
            i += 1
    if len(positional) != 1:
        print("usage: python3 verify_audit_chain.py <audit.log> "
              "[--expected-head <hash>] [--min-entries <n>]")
        return 2
    ok, msg, _ = verify(positional[0], expected_head=expected_head,
                        min_entries=min_entries)
    if ok:
        print("AUDIT CHAIN VERIFIED  ✓  " + msg)
        return 0
    print("AUDIT CHAIN FAILED  ✗  " + msg)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
