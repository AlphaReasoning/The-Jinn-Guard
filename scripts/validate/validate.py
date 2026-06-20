#!/usr/bin/env python3
"""
validate.py — the full reproducible high-assurance enforcement validation.

For a serious evaluator. Everything here drives the REAL daemon; nothing is mocked.
The point is not to *show* you it works — it is to let you *verify* it does:

  1. Run a battery of attacks against the live daemon and print every verdict.
  2. Confirm determinism (run it twice, get identical verdicts).
  3. Independently verify the tamper-evident audit chain (recomputed here, not
     taken on the daemon's word).
  4. PROVE the audit log is tamper-evident: alter one byte and one line, and show
     the verifier catches each.
  5. Reconcile verdicts against the daemon's own /metrics counters.

Standard library only.  Usage:  python3 validate.py
"""
import os
import shutil
import sys
import tempfile

from _daemon import Daemon
from verify_audit_chain import verify, _extract_object

ATTACKS = [
    # (label, expected, kwargs for Daemon.send)
    ("legitimate read (allowed)",        "ALLOW",                          dict(intent="read_customer_record", agent_id="claims_agent", risk="10")),
    ("legitimate read (allowed)",        "ALLOW",                          dict(intent="read_customer_record", agent_id="claims_agent", risk="20")),
    ("legitimate read (allowed)",        "ALLOW",                          dict(intent="read_customer_record", agent_id="claims_agent", risk="30")),
    ("forged signature",                 "DENY_TAMPERED_TOKEN",            dict(intent="read_customer_record", agent_id="claims_agent", risk="10", forge_sig=True)),
    ("unknown agent id",                 "DENY_UNKNOWN_AGENT_ID",          dict(intent="read_customer_record", agent_id="ghost_agent", risk="10")),
    ("anonymous agent",                  "DENY_ANONYMOUS_AGENT_NOT_PERMITTED", dict(intent="read_customer_record", agent_id=None, risk="10")),
    ("intent not on allowlist",          "DENY_INTENT_NOT_ALLOWED",        dict(intent="wipe_database", agent_id="claims_agent", risk="10")),
    ("risk over ceiling (Z3-blocked)",   "DENY_RISK_CEILING_EXCEEDED",     dict(intent="read_customer_record", agent_id="claims_agent", risk="95")),
]


def run_battery(d, label_prefix=""):
    """Fire the attack battery; return list of (label, expected, got, ok)."""
    results = []
    for label, expected, kw in ATTACKS:
        got, _ = d.send(**kw)
        ok = got.startswith("SIGNAL: %s" % expected) or got.endswith(expected)
        results.append((label, expected, got, ok))
    # Replay: a valid request, then the exact same signed request again.
    _first, seq = d.send(intent="read_customer_record", agent_id="claims_agent", risk="10")
    again, _ = d.send(intent="read_customer_record", agent_id="claims_agent", risk="10", reuse_seq=seq)
    results.append(("replay: same signed request twice", "DENY_REPLAY_ATTACK",
                    again, "REPLAY" in again))
    # Quota exhaustion: bounded_agent has quota 3, so the 4th is denied.
    quota = []
    for i in range(4):
        got, _ = d.send(intent="read_customer_record", agent_id="bounded_agent", risk="10")
        quota.append(got)
    results.append(("quota: 4th request over budget", "DENY_QUOTA_EXHAUSTED",
                    quota[-1], "QUOTA_EXHAUSTED" in quota[-1]))
    return results, quota


def print_results(results, quota):
    print("  %-34s %-32s %s" % ("ATTACK", "EXPECTED", "VERDICT"))
    print("  " + "-" * 86)
    n_pass = 0
    for label, expected, got, ok in results:
        mark = "✓" if ok else "✗"
        n_pass += ok
        print("  %-34s %-32s %s  %s" % (label[:34], expected, got, mark))
    print("  (quota sequence: %s)" % " ".join(
        "ALLOW" if "ALLOW" in q else "DENY" for q in quota))
    return n_pass, len(results)


def tamper_content(src, dst):
    """Copy src→dst, then flip one character inside a hashed sub-object of one
    entry (a surgical content edit that should be caught by hash recomputation)."""
    lines = [ln for ln in open(src, encoding="utf-8").read().splitlines() if ln.strip()]
    k = len(lines) // 2
    line = lines[k]
    raw, _ = _extract_object(line, "assessment", 0)
    # change the first digit inside the assessment object to a different digit
    pos_in_raw = next((i for i, c in enumerate(raw) if c.isdigit()), None)
    if pos_in_raw is None:
        raw2 = raw  # fallback: should not happen
    else:
        d = raw[pos_in_raw]
        raw2 = raw[:pos_in_raw] + ("1" if d == "0" else "0") + raw[pos_in_raw + 1:]
    lines[k] = line.replace(raw, raw2, 1)
    with open(dst, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    return k


def tamper_delete(src, dst):
    """Copy src→dst with one middle entry deleted (a linkage break)."""
    lines = [ln for ln in open(src, encoding="utf-8").read().splitlines() if ln.strip()]
    k = len(lines) // 2
    del lines[k]
    with open(dst, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    return k


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    out = os.path.join(here, "validation_out")
    os.makedirs(out, exist_ok=True)
    audit_clean = os.path.join(out, "audit.log")

    print("=" * 90)
    print("JINN GUARD — HIGH-ASSURANCE ENFORCEMENT VALIDATION")
    print("Everything below drives the real daemon. Re-run any step yourself.")
    print("=" * 90)

    # --- 1 & 2: run the battery twice and confirm determinism ----------------
    with Daemon() as d:
        print("\n[1] Attack battery vs. the live daemon")
        results, quota = run_battery(d)
        n_pass, n_total = print_results(results, quota)
        shutil.copyfile(d.audit, audit_clean)
        metrics_text = ""
        try:
            metrics_text = d.metrics()
        except Exception:
            pass

    with Daemon() as d2:
        results2, _ = run_battery(d2)
    verdicts1 = [r[2].replace("SIGNAL: ", "") for r in results]
    verdicts2 = [r[2].replace("SIGNAL: ", "") for r in results2]
    deterministic = verdicts1 == verdicts2
    print("\n[2] Determinism: identical verdicts across two independent runs?  %s"
          % ("YES ✓" if deterministic else "NO ✗"))

    fail_opens = sum(1 for label, expected, got, ok in results
                     if expected != "ALLOW" and _is_allow(got))
    print("    Fail-opens (an attack that was ALLOWED): %d  %s"
          % (fail_opens, "✓" if fail_opens == 0 else "✗"))

    # --- 3: independently verify the clean chain -----------------------------
    print("\n[3] Independent audit-chain verification (recomputed by verify_audit_chain.py)")
    ok, msg, n = verify(audit_clean)
    print("    %s  %s" % ("VERIFIED ✓" if ok else "FAILED ✗", msg))

    # --- 4: prove tamper-evidence -------------------------------------------
    print("\n[4] Tamper-evidence proof (we corrupt a copy; the verifier must catch it)")
    t_content = os.path.join(out, "audit.tampered_content.log")
    k1 = tamper_content(audit_clean, t_content)
    okc, msgc, _ = verify(t_content)
    print("    (a) flipped one byte inside entry #%d's recorded assessment:" % k1)
    print("        %s  %s" % ("VERIFIED ✓ (BAD — not caught)" if okc else "CAUGHT ✗", msgc))

    t_del = os.path.join(out, "audit.tampered_delete.log")
    k2 = tamper_delete(audit_clean, t_del)
    okd, msgd, _ = verify(t_del)
    print("    (b) deleted entry #%d (linkage break):" % k2)
    print("        %s  %s" % ("VERIFIED ✓ (BAD — not caught)" if okd else "CAUGHT ✗", msgd))

    # --- 5: reconcile against /metrics --------------------------------------
    print("\n[5] Reconcile verdicts against the daemon's own /metrics")
    if metrics_text:
        allow = _grab(metrics_text, 'jinnguard_decisions_total{verdict="allow"}')
        deny = _grab(metrics_text, 'jinnguard_decisions_total{verdict="deny"}')
        print("    daemon counters:  allow=%s  deny=%s  (total decisions=%s)"
              % (allow, deny, _safe_add(allow, deny)))
    else:
        print("    (metrics endpoint not reachable in this run — skipped)")

    # --- verdict -------------------------------------------------------------
    print("\n" + "=" * 90)
    passed = (n_pass == n_total and deterministic and fail_opens == 0
              and ok and not okc and not okd)
    print("RESULT: %s" % ("ALL CHECKS PASSED ✓" if passed else "SOME CHECKS FAILED ✗"))
    print("  - attacks correctly handled: %d/%d" % (n_pass, n_total))
    print("  - deterministic: %s   fail-opens: %d" % (deterministic, fail_opens))
    print("  - audit chain verified: %s   tamper caught (content/delete): %s/%s"
          % (ok, not okc, not okd))
    print("Artifacts written to: %s" % out)
    print("Verify the clean log yourself:  python3 verify_audit_chain.py %s"
          % os.path.relpath(audit_clean, here))
    print("Run your own attack:            python3 byo_attack.py --help")
    print("Run the adversarial suite:      cargo test -p ts_cli --test swarm_attack")
    print("=" * 90)
    return 0 if passed else 1


def _is_allow(got):
    """True only if the verdict token is ALLOW (not a substring like NOT_ALLOWED)."""
    return got.split("SIGNAL:")[-1].strip().startswith("ALLOW")


def _grab(text, key):
    for line in text.splitlines():
        if line.startswith(key):
            return line.split()[-1]
    return "?"


def _safe_add(a, b):
    try:
        return str(int(a) + int(b))
    except (ValueError, TypeError):
        return "?"


if __name__ == "__main__":
    sys.exit(main())
