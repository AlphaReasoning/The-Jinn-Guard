#!/usr/bin/env python3
"""
byo_attack.py — Bring Your Own Attack.

Don't trust our scripted demo: craft your own proposal and watch the REAL daemon
rule on it. Boots a private sandboxed daemon, sends exactly the request you
describe on the command line, prints the verdict, and (optionally) verifies the
resulting audit chain.

Examples:
  # A legitimate request (should be ALLOWED):
  python3 byo_attack.py --agent claims_agent --intent read_customer_record --risk 10

  # Forge the signature (should be DENY_TAMPERED_TOKEN):
  python3 byo_attack.py --agent claims_agent --intent read_customer_record --risk 10 --forge

  # An unknown agent (should be DENY_UNKNOWN_AGENT_ID):
  python3 byo_attack.py --agent ghost --intent read_customer_record --risk 10

  # Over the risk ceiling (should be DENY_RISK_CEILING_EXCEEDED):
  python3 byo_attack.py --agent claims_agent --intent read_customer_record --risk 99

  # An intent the agent isn't allowed (should be DENY_INTENT_NOT_ALLOWED):
  python3 byo_attack.py --agent claims_agent --intent wipe_database --risk 10
"""
import argparse
import os
import sys

from _daemon import Daemon
from verify_audit_chain import verify


def main():
    ap = argparse.ArgumentParser(description="Send one hand-crafted proposal to the real daemon.")
    ap.add_argument("--agent", default="claims_agent",
                    help="agent_id to claim (use a bogus one to test identity)")
    ap.add_argument("--intent", default="read_customer_record", help="intent name")
    ap.add_argument("--risk", default="10", help="declared action_risk_score")
    ap.add_argument("--forge", action="store_true", help="send an all-zero (forged) signature")
    ap.add_argument("--anonymous", action="store_true", help="send no agent_id at all")
    ap.add_argument("--version", type=int, default=1, help="protocol version byte")
    ap.add_argument("--repeat", type=int, default=1, help="send N times (e.g. to exhaust quota)")
    args = ap.parse_args()

    agent = None if args.anonymous else args.agent

    with Daemon() as d:
        print("--- your request ---")
        print("  agent      : %s" % (agent if agent else "(anonymous)"))
        print("  intent     : %s" % args.intent)
        print("  risk       : %s" % args.risk)
        print("  signature  : %s" % ("FORGED (all zeros)" if args.forge else "valid HMAC"))
        print("  sends      : %d" % args.repeat)
        print("--- daemon verdicts ---")
        any_allow_of_attack = False
        for i in range(args.repeat):
            sig, _ = d.send(args.intent, agent, args.risk,
                            forge_sig=args.forge, version=args.version)
            print("  [%d] %s" % (i + 1, sig))

        # Independently verify the audit chain the daemon just wrote.
        print("--- audit chain (verified by this script, not the daemon) ---")
        if os.path.exists(d.audit) and os.path.getsize(d.audit) > 0:
            ok, msg, n = verify(d.audit)
            print("  %s  (%s)" % ("VERIFIED ✓" if ok else "FAILED ✗", msg))
        else:
            print("  (no governed-decision entries were written — the request was "
                  "rejected at the integrity/identity gate, before the audit stage)")

    print("\nNote: a forged/identity-failed request is rejected at the integrity gate "
          "before it reaches the governed-decision audit stage; a well-formed but "
          "disallowed request is recorded. Try both and compare.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
