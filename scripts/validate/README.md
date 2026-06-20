# Jinn Guard — High-Assurance Enforcement Validation

A reproducible validation harness for serious evaluators. It drives the **real**
Jinn Guard daemon (nothing mocked) and is built around one principle:

> Don't trust the demo — **verify it yourself.**

Everything is standard-library Python 3 and a release build of the daemon. No
network, no cloud, no external dependencies — runs on an air-gapped box.

## Prerequisites

- A release build of the daemon: `cargo build --release -p ts_cli`
  (or set `JINNGUARD_BENCH_BINARY=/path/to/ts_cli`).
- Python 3.8+.

## Run it (10 minutes)

```bash
cd scripts/validate

# 1. The full reproducible validation: attack battery, determinism, audit-chain
#    verification, tamper-evidence proof, and metrics reconciliation.
python3 validate.py

# 2. Independently verify the audit chain the run produced (no daemon involved):
python3 verify_audit_chain.py validation_out/audit.log

# 3. Prove it's tamper-evident by hand: open validation_out/audit.log in an
#    editor, change ANY character inside an entry, save, then:
python3 verify_audit_chain.py validation_out/audit.log     # -> FAILED ✗

# 4. Bring your own attack — craft any request and watch the daemon rule on it:
python3 byo_attack.py --help
python3 byo_attack.py --agent claims_agent --intent read_customer_record --risk 99
python3 byo_attack.py --forge
python3 byo_attack.py --agent bounded_agent --intent read_customer_record --repeat 5

# 5. Run the in-tree adversarial suite yourself:
cargo test -p ts_cli --test swarm_attack
```

## What's in here

| File | Purpose |
|---|---|
| `validate.py` | The full reproducible validation run. Start here. |
| `verify_audit_chain.py` | Standalone, daemon-free verifier of the tamper-evident hash chain. |
| `byo_attack.py` | Send your own hand-crafted proposal to the real daemon. |
| `_daemon.py` | Boots a private, sandboxed daemon (own socket/policy/secret/audit). |
| `CLAIMS.md` | Every claim → the verdict that proves it → the command you run. |
| `validation_out/` | Artifacts from the last run (audit log + tampered copies). Regenerated. |

## What this proves (and what it doesn't)

**Proves, on any Linux box:** deterministic, fail-closed governance of agent
actions (identity, integrity, least-privilege, Z3 risk ceiling, anti-replay,
quota), and a **cryptographically tamper-evident** audit trail you can verify
without trusting the daemon.

**Does not prove here:** the **kernel-enforcement floor** — that the action is
blocked even when a compromised agent bypasses the userspace socket. That is the
property that makes the guarantee hold against a *non-cooperating* agent, and it
requires BPF-LSM armed on the host (see the repo's kernel validation / the VM
demo). This suite validates everything in the decision and audit path; the kernel
floor is validated separately on a real kernel.

## Reading the result

A clean run prints `RESULT: ALL CHECKS PASSED ✓` with: every attack handled,
identical verdicts across two runs, `fail-opens: 0`, the audit chain verified, and
both tamper attempts caught. Any single failing check flips the result and tells
you exactly which entry/line failed and why.
