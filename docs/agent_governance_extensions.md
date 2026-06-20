# Agent Governance Extensions — Design Notes

**Status: design intent, not implemented.** These notes record two gaps surfaced
by the [Jinn Guard teaching lab](../lab/README.md). The lab teaches a four-verdict
model — `ALLOW`, `DENY`, `CANARY_TRIGGERED`, `HUMAN_REVIEW` — but the daemon today
emits only the first two. Rather than let the teaching model quietly overclaim,
this note documents how the other two would map onto the real pipeline, so the
lesson and the product converge honestly.

This is the same discipline the lab itself teaches: be explicit about the gap
between what the model *claims* and what the system *enforces*.

---

## Current verdict surface (implemented)

The daemon returns a binary terminal decision, logged to the hash-chained audit
log:

- `SIGNAL: ALLOW`
- `SIGNAL: DENY_<reason>` — `DENY_UNKNOWN_AGENT_ID`, `DENY_ANONYMOUS_AGENT_NOT_PERMITTED`,
  `DENY_INTENT_NOT_ALLOWED`, `DENY_RISK_CEILING_EXCEEDED`, `DENY_REPLAY_ATTACK`,
  `DENY_QUOTA_EXHAUSTED`, `DENY_TAMPERED_TOKEN`

There is no canary concept and no non-terminal/escalation state.

---

## Gap 1 — Canary / honeypot detection (`CANARY_TRIGGERED`)

**Concept.** A request that touches a decoy resource — a path, intent, or
credential that no legitimate agent should ever reference — is not merely denied;
it is flagged as a probable probe. The only way to hit a canary is to be looking
for something you shouldn't.

**Why it's distinct from `DENY`.** A `DENY` says *"you asked for something not
allowed."* A canary hit says *"you asked for something that exists only as a
trap"* — a materially stronger signal of adversarial intent, worth alerting on,
not just blocking.

**Where it maps onto the pipeline:**
- **Policy** (`policy.yaml`): add a `canary_resources` set (decoy paths, intents,
  fake credentials).
- **Decision path:** evaluate canary match *before* the normal allow/deny so a hit
  short-circuits. For wire compatibility, emit it inside the deny family
  (`SIGNAL: DENY_CANARY_TRIPWIRE`) while recording a distinct audit/alert event.
- **Telemetry:** new `jinnguard_canary_trips_total` counter on the existing
  `/metrics` endpoint; optional out-of-band alert.
- **Kernel tie-in (later):** BPF-LSM could plant canary inodes/paths so a touch is
  caught at the kernel floor even if the agent bypasses the userspace socket.

**Status:** not implemented. No `canary_resources` policy key exists today.

---

## Gap 2 — Human-in-the-loop review (`HUMAN_REVIEW`)

**Concept.** Some actions are neither clearly safe nor clearly forbidden (e.g.
exfil-shaped but possibly legitimate). Instead of forcing a binary verdict, the
daemon parks the decision pending a human ruling.

**Why it's distinct.** Today such cases must be pre-decided as allow or deny. A
third, *non-terminal* state lets policy say "escalate" without either failing
open or over-blocking legitimate work.

**Where it maps onto the pipeline:**
- **Policy:** a `review_intents` set, and/or a risk band (e.g.
  `ceiling - margin .. ceiling`) that routes to review instead of deny.
- **Decision path:** a new non-terminal verdict `SIGNAL: HOLD_PENDING_REVIEW`.
  The request **blocks (fails closed)** until a verdict arrives or a timeout
  resolves it.
- **Requires:** a control channel to deliver the human verdict (see Phase 2's
  dual-channel IPC in [ROADMAP.md](../ROADMAP.md)), a pending-decision store, and a
  timeout policy.
- **Timeout rule:** on timeout, **deny** — never fail open.
- **Audit:** the hold, the reviewer's identity, and the final verdict all chain
  into the hash-chained audit log.

**Status:** not implemented. The daemon is binary `ALLOW`/`DENY` with no pending
state or review channel.

---

## Design invariants (both extensions)

1. **Fail closed.** Any new code path that cannot resolve defaults to `DENY`,
   never `ALLOW` — consistent with the measured 0-fail-open property.
2. **Everything logged.** Canary trips and review holds/resolutions all enter the
   hash-chained audit log. (This is the lab's bug-fixer lesson, made permanent.)
3. **Wire compatibility.** Prefer extending the `DENY_*` reason space and adding
   new event types over breaking the 5-byte framed protocol.
