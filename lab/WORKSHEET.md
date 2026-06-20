# Jinn Guard Lab — Team Worksheets

Each team owns one deliverable. You have ~45 minutes. Keep it small and correct.

---

## Policy Team — owns `policy.json`

Define the rules the guard enforces. Fill in the table, then encode it in
`policy.json`.

| Intent | Verdict it should get | Why |
| --- | --- | --- |
| `read_public_file` | ALLOW | |
| `delete_system_files` | DENY | |
| `send_customer_data` | HUMAN_REVIEW | |
| `cleanup_workspace` | ALLOW *only* under `/tmp/student_workspace` | |
| _(add one of your own)_ | | |

**Deliverable:** a working `policy.json` with at least one allowed, one denied,
one review intent, and one scope-restricted intent.

**Discuss:** what is your *default* for an intent nobody listed — allow or deny?
Why is "deny by default" the safer choice?

---

## Threat Team — owns `actions.json`

Write the attacks. Your job is to make the guard's life hard.

**Deliverable:** add to `actions.json`:
- one obviously malicious action (should DENY),
- one **canary trap** — an action whose *intent looks innocent* but whose target
  is a honeypot path (should CANARY_TRIGGERED),
- one "borderline" action you genuinely aren't sure about.

**Discuss:** which of your attacks would slip through if the guard only checked
the *intent name* and ignored the *target*?

---

## Code Team — owns the checker

Read `checker_starter.py`. You don't have to rewrite it — extend it.

**Deliverable:** add ONE new rule to `decide()`. Ideas:
- block any target containing `..` (path traversal),
- send anything over risk 90 straight to DENY instead of HUMAN_REVIEW,
- add a new verdict of your own and document when it fires.

**Discuss:** the order of checks in `decide()` matters. Why is the canary check
*first*? What breaks if you move it last?

---

## Audit Team — owns the decision log (and finds the bug)

Run `python3 lab/checker_starter.py` and look at the audit log at the bottom.

**Deliverable:** answer in writing —
1. How many actions were processed?
2. How many appear in the audit log?
3. Which verdicts are **missing** from the log, and why is that dangerous?
4. Fix it. (Compare against `checker_solution.py` only after you've tried.)

**The lesson to present:** the guard *blocked* the attacks correctly — but a
blocked attack that leaves no record is one nobody can detect, investigate, or
prove. Enforcement without audit is not security.

---

## Presenter Team — owns the story

You get 2 minutes. Use the one-page model from the README:

```
AI Agent -> Semantic Intent -> Policy -> Canary Detection
         -> ALLOW / DENY / HUMAN_REVIEW / CANARY_TRIGGERED -> Audit Log
```

**Deliverable:** a 2-minute explanation that answers:
- What is the difference between the *literal action* and the *semantic intent*?
- What did the canary catch that the plain allow-list would have missed?
- Why is the audit log not optional?

**The takeaway to land:** the future of AI security is not only controlling what
an AI *says* — it is controlling what an AI is *allowed to do*, and proving what
happened.
