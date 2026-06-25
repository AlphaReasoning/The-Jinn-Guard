# What Jinn Guard claims — and exactly how you verify each claim yourself

This suite is built so you don't have to take our word for anything. Every claim
below maps to an observable verdict from the **real** daemon and a command **you**
run to reproduce it. Nothing here is mocked.

Run the whole thing first: `python3 validate.py`. Then reproduce any single line.

| # | Claim | Threat it stops | Verdict you'll see | Verify it yourself |
|---|---|---|---|---|
| 1 | **Request integrity** — a tampered/forged request can't be honored | Forged authorization | `DENY_TAMPERED_TOKEN` | `python3 byo_attack.py --forge` |
| 2 | **Agent identity required** — unknown identities are rejected | Impersonation | `DENY_UNKNOWN_AGENT_ID` | `python3 byo_attack.py --agent ghost` |
| 3 | **No anonymous action** (policy-gated) | Unattributed action | `DENY_ANONYMOUS_AGENT_NOT_PERMITTED` | `python3 byo_attack.py --anonymous` |
| 4 | **Least privilege** — only allow-listed intents | Scope creep / unexpected action | `DENY_INTENT_NOT_ALLOWED` | `python3 byo_attack.py --intent wipe_database` |
| 5 | **Risk ceiling (Z3-verified)** — over-budget actions blocked by proof | Privilege/risk escalation | `DENY_RISK_CEILING_EXCEEDED` | `python3 byo_attack.py --risk 99` |
| 6 | **Anti-replay** — a captured request can't be replayed | Replay | `DENY_REPLAY_ATTACK` | run `validate.py` (replay case) |
| 7 | **Quota / rate bound** — bounded agents can't exceed budget | Runaway / drift | `DENY_QUOTA_EXHAUSTED` | `python3 byo_attack.py --agent bounded_agent --repeat 5` |
| 8 | **Deterministic & fail-closed** — same input → same verdict, no attack ever allowed | Nondeterministic bypass | identical verdicts twice, `fail-opens: 0` | `validate.py` runs the battery twice |
| 9 | **Tamper-evident audit** — the decision log can't be silently altered | Evidence tampering | verifier reports `CAUGHT` | `python3 verify_audit_chain.py <edited log>` |
| 10 | **Transparency** — verdicts reconcile with the daemon's own counters | Hidden behavior | `allow`/`deny` totals match | `validate.py` step 5 / `curl /metrics` |
| 11 | **Canary tripwire** — touching a decoy resource is denied *before* the allowlist, as a compromise signal | Recon / compromised agent probing | `DENY_CANARY_TRIPWIRE` | `python3 byo_attack.py --agent claims_agent --intent read_canary_decoy_a91f` |

## What "verify the audit chain yourself" means (claim 9)

`verify_audit_chain.py` recomputes the SHA-256 hash chain **independently of the
daemon**, using the daemon's own serialized bytes (extracted from each log line,
not re-serialized — so there are no false alarms from float formatting). It checks,
per entry:

1. the index increments by one (no insert/delete/reorder),
2. each `prev_hash` equals the previous entry's `hash` (linkage),
3. the recomputed hash equals the stored `hash` (content binding).

`validate.py` then **proves** it's tamper-evident by corrupting a copy two ways —
flipping one byte inside a recorded decision, and deleting one entry — and showing
the verifier catches each. Do it by hand: edit `validation_out/audit.log` in any
text editor and re-run the verifier.

## Honest scope of this suite

- This validates the **userspace governance decision** and the **audit-integrity**
  guarantees end to end, on the real daemon, on any Linux box — no special kernel
  config required.
- It does **not**, by itself, demonstrate the **kernel-enforcement floor** (that an
  action is blocked even when the agent bypasses the userspace socket entirely).
  That requires BPF-LSM armed on the host and is shown by the separate kernel-floor
  script — see the repo's kernel validation. The kernel floor is what makes the
  guarantee hold against a *non-cooperating* agent; this suite proves everything
  above it.
- Early integrity/identity rejects (e.g. a forged token) are denied **before** the
  governed-decision audit stage, so they appear in the live verdict and the
  `/metrics` counters but not as audit-chain entries. Governed decisions (allow,
  risk, quota, replay) are what populate the tamper-evident chain.

## Claims pending code
- Claim 5 (Risk ceiling): The documentation claims this is backed by a Z3 constraint check (`execute_totality_audit()`), but the actual implementation in `main.rs` only performs a simple float comparison (`assessment.fused_risk > current_policy.upper_safety_boundary`) and does not invoke the Z3 solver for the risk ceiling check.
