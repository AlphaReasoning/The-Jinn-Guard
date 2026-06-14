# Jinn Guard — Live Demo Guide

A complete, self-contained demonstration you can run in front of anyone — a
customer, an investor, a professor, a security team — and walk through as if you
were explaining it to a 5th grader. **Every verdict on the screen is produced by
the real product**, not a mockup.

---

## Run it

```bash
bash scripts/demo.sh           # interactive — press ENTER to advance each step
bash scripts/demo.sh --auto    # autoplay (good for screen recordings)
```

That's it. The script builds the real daemon if needed, launches it in a private
sandbox, runs the walkthrough, and cleans everything up when you're done.

- **Time:** ~4–6 minutes interactive.
- **Needs:** Linux, Python 3, and Rust (only for the one-time build). No root, no
  Docker, no internet.
- **Safety:** it governs only a throwaway demo agent, binds its metrics to
  localhost, and deletes its socket/policy/key on exit. It cannot touch your
  files or lock you out. See "Safety FAQ" below.

---

## The one-sentence pitch

> AI agents can now run commands, open files, and reach the network on their own.
> **Jinn Guard is the security checkpoint that sits between the agent and the
> computer** — checking *who's asking*, *whether it's allowed*, and *whether it's
> safe* before anything happens, fast enough that nobody notices.

---

## What each step shows (your talking points)

The dashboard has six steps. Here's what to say at each one.

### Step 1 — Start the real guard
> "I'm starting the actual product right now, on this laptop. It loads a tiny
> rulebook: one AI agent — a claims processor — is allowed to do exactly two
> things. Everything else is refused by default. That 'smallest possible door'
> idea is the whole philosophy."

### Step 2 — The good robot does its job  → **ALLOWED**
> "First, normal life. The trusted agent asks to do something on its approved
> list. Jinn Guard checks its ID, the request, and the risk — all fine —
> and gets out of the way. The point: **good behavior never feels it.**"

### Step 3 — Seven real attacks → **all BLOCKED, live**
Walk these one at a time. Each is a different way to break in, and each is
refused by a *different* layer — say the bold part out loud:

| # | The attack (plain English) | Why it fails | Real reason code |
|---|---|---|---|
| 1 | **Fake the ID badge** (tamper with a signed request) | cryptographic identity | `DENY_TAMPERED_TOKEN` |
| 2 | **Stranger with an unknown ID** | not on the staff list | `DENY_UNKNOWN_AGENT_ID` |
| 3 | **No ID badge at all** | anonymous refused | `DENY_ANONYMOUS_AGENT_NOT_PERMITTED` |
| 4 | **Hijack the trusted agent** → "exfiltrate the database" | not on its job list | `DENY_INTENT_NOT_ALLOWED` |
| 5 | **An approved job at a dangerous risk level** | math proof blocks it | `DENY_RISK_CEILING_EXCEEDED` |
| 6 | **Record a real request and replay it** | replay caught | `DENY_REPLAY_ATTACK` |
| 7 | **Flood to "wear the guard down"** | hard budget holds | `DENY_QUOTA_EXHAUSTED` |

**Spend your energy on #4** — it's the headline:
> "This is the scary one. The agent's ID is 100% genuine. It was *tricked* by a
> malicious prompt into asking for something off its list. A real badge is **not
> a blank check** — the action itself has to be approved. That's the attack
> everyone in the agent world is worried about, and you just watched it bounce."

### Step 4 — The guard's own counters
> "I'm not asking you to trust my numbers. This is the daemon reporting on
> *itself* — every request counted, every block recorded **with its reason**.
> In production this feeds straight into Grafana so an ops team watches it live."

### Step 5 — The receipts
> "Measured on real hardware, and you can reproduce every number with the two
> commands on screen. Half of all decisions in **257 millionths of a second**.
> **12 of 12** attack tests pass across 1,200+ hostile requests with **zero**
> fail-opens. 122 automated tests in total."

### Step 6 — Safety
> "The first question for anything that can say *no* inside a kernel is: can it
> brick my machine? No — and here's exactly why." (Then read the four points.)

### Closing — Why it wins
> "Most AI-governance tools live *inside* the app — the same place a hijacked
> agent already runs, so it can often go around them. Jinn Guard puts the last
> checkpoint in the **Linux kernel, underneath the agent**. You can't sweet-talk
> a kernel hook, and the agent can't reach around something below it."

---

## Safety FAQ (the questions you'll get)

**Can it lock me out of my own computer?**
No. Kernel enforcement is **cgroup-scoped** — only the specific agent sandbox you
point it at is governed. Your desktop, your shell, and every other process are
structurally out of scope and pass through untouched. A wrong scope makes a
*test* fail, not your machine. Validated armed on a single laptop with no lockout.

**What if the safety checker itself hangs?**
It **fails closed.** The formal proof (Z3) runs under a 250 ms timeout; if it
can't prove an action safe in time, the answer is *no*, never "sure."

**Do I have to turn on blocking to try it?**
No. It runs **audit-only** first — watch and log, block nothing — so you can build
trust before you ever arm enforcement.

**What does it *not* claim?** (Say this unprompted — it builds credibility.)
The risk *score* is still a heuristic, so the math proof is only as good as the
number fed into it. That's why identity, the approved-jobs allow-list, and kernel
enforcement are the real walls, with risk scoring as one more layer. This is
written down honestly in [`THREAT_MODEL.md`](THREAT_MODEL.md) §8.

**Is the demo data real?**
Yes. The dashboard launches the actual `ts_cli` daemon and sends real requests
over its real socket. The blocks you see are the production code path. The
benchmark numbers in Step 5 come from [`BENCHMARKS-01.md`](BENCHMARKS-01.md)
and are reproducible with `cargo bench` / `cargo test --test swarm_attack`.

---

## If something goes wrong on stage

- **"daemon binary not found"** → run `cargo build --release -p ts_cli` once, then
  re-run the demo.
- **Metrics panel says unavailable** → harmless; another process is using the
  metrics port. Re-run with `bash scripts/demo.sh --metrics-port 19950`.
- **You want it to never pause** → add `--auto`.
- **Colors look wrong** (logged to a file) → add `--no-color` or set `NO_COLOR=1`.

---

## Deeper material to have open in a second tab

- [`README.md`](README.md) — the at-a-glance numbers and architecture.
- [`BENCHMARKS-01.md`](BENCHMARKS-01.md) — full latency/throughput/attack tables.
- [`OWASP-MAPPING.md`](OWASP-MAPPING.md) — coverage vs the OWASP Agentic Top 10.
- [`THREAT_MODEL.md`](THREAT_MODEL.md) — trust boundaries and honest residual risk.
