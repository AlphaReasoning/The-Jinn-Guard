#!/usr/bin/env python3
"""
Jinn Guard Lab — mini action-governance checker  (SOLUTION / bug fixed)

Same engine as checker_starter.py, with the planted audit flaw fixed:

    THE BUG:  the starter only logged ALLOW decisions, so every DENY,
              CANARY_TRIGGERED, and HUMAN_REVIEW happened silently — the system
              made the right call but could not PROVE it.

    THE FIX:  log EVERY decision through a single chokepoint, so the audit
              trail is complete by construction. A blocked attack that leaves
              no trace is one you can't detect, investigate, or report.

Run it (standard library only):

    python3 lab/checker_solution.py
"""
import datetime
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))


def load(name):
    with open(os.path.join(HERE, name)) as f:
        return json.load(f)


AUDIT = []


def log_decision(action, decision, reason):
    AUDIT.append({
        "time": datetime.datetime.now().isoformat(timespec="seconds"),
        "intent": action.get("intent"),
        "target": action.get("target"),
        "decision": decision,
        "reason": reason,
    })


def decide(action, policy):
    intent = action.get("intent", "")
    target = action.get("target", "") or ""
    risk = action.get("risk", 0)

    # 1. Canary / honeypot check FIRST — catch it even if the intent looks fine.
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

    # 6. Deny by default.
    return "DENY", "deny-by-default (intent not in policy)"


def main():
    policy = load("policy.json")
    actions = load("actions.json")

    print(f"{'INTENT':<22}{'TARGET':<36}VERDICT")
    print("-" * 74)
    for action in actions:
        decision, reason = decide(action, policy)

        # THE FIX: every decision is logged, no exceptions. The audit trail is
        # complete by construction — there is no code path that decides without
        # also recording it.
        log_decision(action, decision, reason)

        print(f"{action.get('intent', ''):<22}"
              f"{(action.get('target', '') or ''):<36}{decision}")

    print("\n=== AUDIT LOG (what we can PROVE happened) ===")
    for row in AUDIT:
        print(f"  {row['time']}  {row['decision']:<16} "
              f"{row['intent']}  ->  {row['reason']}")

    # Quick proof the trail is complete: counts per verdict.
    counts = {}
    for row in AUDIT:
        counts[row["decision"]] = counts.get(row["decision"], 0) + 1
    print("\n=== AUDIT SUMMARY ===")
    print(f"  actions seen: {len(actions)}   logged: {len(AUDIT)}   "
          f"(complete: {len(AUDIT) == len(actions)})")
    for verdict, n in sorted(counts.items()):
        print(f"  {verdict:<16} {n}")


if __name__ == "__main__":
    main()
