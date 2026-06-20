# Jinn Guard Lab: From Semantic Intent to Binary Enforcement

A hands-on lab that teaches the core idea behind [Jinn Guard](../README.md)
**without** touching the kernel/eBPF layer yet. Students build a tiny model of
an action-governance system and discover, by breaking it, the lesson that drives
the whole project:

> **A security system must detect the gap between what the policy *thinks* is
> protected and what the system *actually* enforces — and it must be able to
> prove what happened.**

The future of AI security isn't only controlling what an AI *says*. It's
controlling what an AI is *allowed to do* — and proving what happened.

---

## The question this lab answers

**Can the team detect when an AI agent crosses a boundary it should never touch?**

That single question ties together the four ideas this lab is about:

- **Semantic intent** — what is the action *really* trying to do?
- **Missed bugs** — where does the policy disagree with the enforcement?
- **Honeypots / canaries** — traps that catch what the policy missed.
- **Action governance** — allow / deny / review / canary, then *log it all*.

---

## The mission

An AI agent proposes actions. Jinn Guard checks the **intent** against policy and
responds with exactly one of four verdicts:

| Verdict | Meaning |
| --- | --- |
| `ALLOW` | Permitted — the action proceeds. |
| `DENY` | Forbidden — the action is blocked. |
| `CANARY_TRIGGERED` | The action touched a honeypot/canary — likely an attacker probing. |
| `HUMAN_REVIEW` | A human has to decide. |

This lab is the conceptual version of the same pipeline — but be precise about
what's real, because that precision *is* the lesson.

---

## How this maps to the real Jinn Guard

Two of the four verdicts are exactly what the real daemon emits. The other two
are concepts **this lab adds** — they are where you'd *extend* the system, not
what it does today. Knowing which is which is part of the exercise: a security
model you can't trust is one where you've lost track of what's actually enforced
versus what's only aspirational.

| Lab concept | In the real Jinn Guard? |
| --- | --- |
| Agent proposes an action → guard checks intent **before** tool execution | ✅ Exactly the model |
| `ALLOW` / `DENY` | ✅ Real verdicts (`SIGNAL: ALLOW`, `SIGNAL: DENY_*`) |
| Deny-by-default | ✅ Real |
| Policy-driven rules | ✅ Real (`policy.yaml`) |
| Risk ceiling | ✅ Real (`DENY_RISK_CEILING_EXCEEDED`) — but the real one is enforced by a **Z3 SMT solver**; this lab simplifies it to a number comparison |
| Scope / path restriction | ✅ Real (execution-broker denylist + cgroup scoping) |
| Logging **every** decision | ✅ Real and central — the daemon keeps a **hash-chained** audit log; the bug-fixer moment below is faithful to a real property |
| `CANARY_TRIGGERED` | ❌ **Not a Jinn Guard feature today.** Honeypots/canaries are a concept this lab introduces — roadmap, not current behavior. |
| `HUMAN_REVIEW` | ❌ **Not today.** The real daemon is binary `ALLOW` / `DENY`; human-in-the-loop escalation is a concept this lab introduces. |

So the lab deliberately teaches a **superset** of what the product currently
enforces. That's good for learning — canaries and human review are worth
understanding — as long as nobody claims "Jinn Guard does all four." It does the
top of this table for real; the bottom two are yours to imagine and build.

> **Meta-lesson:** notice that this table is the same move the whole lab is
> about — detecting the gap between what a security model *claims* and what it
> *actually enforces*, and being honest about it. Apply that to your own designs.

---

## Warm-up: classify four actions

For **each** action below, answer the five questions:

| Action | Target |
| --- | --- |
| `read_public_file` | `/var/www/index.html` |
| `delete_system_files` | `/etc/passwd` |
| `read_public_file` | `/admin/canary_secret.txt` |
| `send_customer_data` | `https://partner.example.com` |

1. What is the **literal** action?
2. What is the **semantic intent**?
3. What is the **risk**?
4. Should it be **allowed, denied, reviewed, or treated as a canary hit**?
5. **What would happen if the enforcement layer missed it?**

> Note the third row: the *intent* (`read_public_file`) looks harmless, but the
> *target* is a canary. A good system catches it anyway. That's the honeypot
> lesson — canaries catch what the intent allowlist alone would wave through.

---

## Team roles

| Team | Job |
| --- | --- |
| **Policy Team** | Define the allowed, denied, and review actions (`policy.json`). |
| **Threat Team** | Create attack examples and canary traps (`actions.json`). |
| **Code Team** | Build / extend the mini allow–deny checker. |
| **Audit Team** | Design the decision log (and find the bug — see below). |
| **Presenter Team** | Explain the security lesson in 2 minutes. |

Each team's concrete deliverable is in [`WORKSHEET.md`](WORKSHEET.md).

---

## Run the lab

No installs, no dependencies — just Python 3:

```bash
python3 lab/checker_starter.py     # the version with the planted flaw
python3 lab/checker_solution.py    # the fixed version
```

The checker reads two data files so students can edit policy and attacks without
touching the engine:

- [`policy.json`](policy.json) — the mini **policy table**.
- [`actions.json`](actions.json) — the list of agent actions (and **canary traps**).

---

## The demo flow

```
AI agent request:  "Clean up this folder."
        │
        ▼
Semantic intent:   is this really cleanup, or could it delete protected files?
        │
        ▼
Policy check:      cleanup_workspace is allowed ONLY under /tmp/student_workspace
        │
        ▼
Canary check:      if it touches /admin/canary_secret.txt → trigger alert
        │
        ▼
Decision:          ALLOW · DENY · CANARY_TRIGGERED · HUMAN_REVIEW
        │
        ▼
Audit log:         record the decision so we can PROVE what happened
```

---

## The bug-fixer moment

The starter (`checker_starter.py`) makes **correct decisions** — it blocks
`delete_system_files`, it catches the canary. But it has one planted flaw:

> The policy blocks dangerous actions, **but the audit layer only logs `ALLOW`
> decisions.** Every `DENY`, `CANARY_TRIGGERED`, and `HUMAN_REVIEW` happens
> silently.

Run the starter and look at the audit log at the bottom. Then ask:

**"Why is that dangerous?"**

Expected answer:

> *Because the system may block the action, but nobody can prove what happened.*
> A blocked attack that leaves no trace is a blocked attack you can't detect,
> investigate, or report. The canary fired — and no one will ever know.

**The fix:** every decision — `ALLOW`, `DENY`, `CANARY_TRIGGERED`,
`HUMAN_REVIEW` — must be logged. Compare your fix against
[`checker_solution.py`](checker_solution.py).

This is the real lesson in miniature: the policy and the enforcement were both
"working," but the system still couldn't be *trusted*, because it couldn't prove
its own behavior. Detecting that gap is the job.

---

## What each team produces

1. A mini **policy table** (`policy.json`).
2. A list of **canary / honeypot traps** (`actions.json`).
3. A simple **action-flow diagram** (the one-pager below).
4. A short **demo or pseudocode checker**.
5. A **2-minute explanation** of the security lesson.

---

## The one-page Action Governance Model

The clean mental model — the deliverable to draw before anyone touches the real
C/eBPF layer:

```
            AI Agent
               │
               ▼
       Semantic Intent Check
               │
               ▼
          Policy Rules
               │
               ▼
   Canary / Honeypot Detection
               │
               ▼
   ALLOW / DENY / HUMAN_REVIEW / CANARY_TRIGGERED
               │
               ▼
           Audit Log
```

Once a team can explain every arrow in that diagram — and why the last box is
not optional — they're ready for the kernel-enforcement layer.
