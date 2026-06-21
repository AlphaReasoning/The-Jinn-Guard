#!/usr/bin/env python3
"""
Jinn Guard Lab — mini action-governance checker  (STARTER / has a planted bug)

A teaching model of the real Jinn Guard idea: before an AI agent is allowed to
*do* something, a guard checks the action's intent against policy and returns one
of four verdicts:

    ALLOW             — permitted, proceed
    DENY              — forbidden, blocked
    CANARY_TRIGGERED  — touched a honeypot/canary; likely an attacker probing
    HUMAN_REVIEW      — needs a human to decide

Run it (standard library only):

    python3 lab/checker_starter.py

⚠️  This STARTER contains ONE intentional flaw for the Bug-Fixer / Audit Team.
    The decisions are correct — but can the system *prove* what happened?
    See lab/README.md -> "The bug-fixer moment".
"""
import datetime
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))


def load(name):
    with open(os.path.join(HERE, name)) as f:
        return json.load(f)


# --------------------------------------------------------------------------- #
#  Audit log  (the planted flaw lives in how this gets *called*, below)
# --------------------------------------------------------------------------- #
AUDIT = []


def log_decision(action, decision, reason):
    AUDIT.append({
        "time": datetime.datetime.now().isoformat(timespec="seconds"),
        "intent": action.get("intent"),
        "target": action.get("target"),
        "decision": decision,
        "reason": reason,
    })


# --------------------------------------------------------------------------- #
#  Decision engine
# --------------------------------------------------------------------------- #
def decide(action, policy):
    intent = action.get("intent", "")
    target = action.get("target", "") or ""
    risk = action.get("risk", 0)

    # 1. Canary / honeypot check FIRST. A canary hit must be caught even when the
    #    intent looks harmless — that is the entire point of a honeypot.
    for trap in policy["canary_paths"]:
        if trap in target:
            return "CANARY_TRIGGERED", f"touched canary {trap!r}"

    # 2. Explicitly denied intents.
    if intent in policy["denied_intents"]:
        return "DENY", "intent is on the deny list"

    # 3. Intents that always require a human.
    if intent in policy["review_intents"]:
        return "HUMAN_REVIEW", "intent requires human review"

    # 4. Risk ceiling.
    if risk > policy["risk_ceiling"]:
        return "HUMAN_REVIEW", f"risk {risk} exceeds ceiling {policy['risk_ceiling']}"

    # 5. Allowed intents — but destructive ones only inside the workspace.
    if intent in policy["allowed_intents"]:
        if intent in policy.get("workspace_only_intents", []):
            if not target.startswith(policy["workspace_root"]):
                return "DENY", f"{intent} only allowed under {policy['workspace_root']}"
        return "ALLOW", "intent allowed by policy"

    # 6. Deny by default — anything not explicitly allowed is denied.
    return "DENY", "deny-by-default (intent not in policy)"


def main():
    policy = load("policy.json")
    actions = load("actions.json")

    print(f"{'INTENT':<22}{'TARGET':<36}VERDICT")
    print("-" * 74)
    for action in actions:
        decision, reason = decide(action, policy)

        # ⚠️  Bug-Fixer / Audit Team: study these two lines carefully.
        #     What gets recorded — and what disappears without a trace?
        if decision == "ALLOW":
            log_decision(action, decision, reason)

        print(f"{action.get('intent', ''):<22}"
              f"{(action.get('target', '') or ''):<36}{decision}")

    print("\n=== AUDIT LOG (what we can PROVE happened) ===")
    if not AUDIT:
        print("  (empty)")
    for row in AUDIT:
        print(f"  {row['time']}  {row['decision']:<16} "
              f"{row['intent']}  ->  {row['reason']}")


if __name__ == "__main__":
    main()
