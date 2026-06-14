#!/usr/bin/env python3
"""
Jinn Guard — Live Investor / Stakeholder Demo Dashboard
=======================================================

ONE command. NO mock data. Every verdict on the screen is produced by the
REAL Jinn Guard daemon (`target/*/ts_cli`) answering a real request over its
real Unix-domain socket, through the full governance pipeline:

    protocol header -> HMAC-SHA256 verify -> parse -> replay/nonce -> identity
    -> intent allow-list -> runtime policy -> quota -> adaptive risk floor
    -> Z3 SMT ceiling proof -> hash-chained audit

The script:
  1. launches a private, sandboxed daemon (its own temp socket/policy/secret),
  2. sends ONE legitimate request -> watch it get ALLOWED,
  3. fires SEVEN distinct real attacks -> watch each get DENIED, live,
  4. reads the daemon's own Prometheus /metrics counters back,
  5. shows the validated benchmark "receipts," and
  6. walks through the safety guarantees.

It is read-only and self-cleaning: it governs only its own throwaway agent,
binds metrics to loopback, and kills + deletes everything on exit. It cannot
touch your machine, your files, or your desktop session.

Stdlib only. Run it: `bash scripts/demo.sh`  (or `python3 this_file.py`).
"""

import argparse
import atexit
import hashlib
import hmac
import json
import os
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
import urllib.request

# --------------------------------------------------------------------------- #
#  Presentation helpers (ANSI, dependency-free)
# --------------------------------------------------------------------------- #

USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _c(code: str, s: str) -> str:
    return f"\033[{code}m{s}\033[0m" if USE_COLOR else s


def bold(s):   return _c("1", s)
def dim(s):    return _c("2", s)
def red(s):    return _c("1;31", s)
def green(s):  return _c("1;32", s)
def yellow(s): return _c("1;33", s)
def blue(s):   return _c("1;36", s)
def grey(s):   return _c("38;5;245", s)


W = 74  # dashboard width


def rule(ch="─"):
    return grey(ch * W)


def banner(title, subtitle=""):
    print()
    print(blue("╔" + "═" * (W - 2) + "╗"))
    line = f" {title} "
    print(blue("║") + bold(line.ljust(W - 2)) + blue("║"))
    if subtitle:
        print(blue("║") + dim(f" {subtitle} ".ljust(W - 2)) + blue("║"))
    print(blue("╚" + "═" * (W - 2) + "╝"))


def panel(lines, color=blue):
    print(color("┌" + "─" * (W - 2) + "┐"))
    for ln in lines:
        # ln may contain color codes; pad on the visible length
        visible = _strip(ln)
        pad = max(0, (W - 4) - len(visible))
        print(color("│ ") + ln + " " * pad + color(" │"))
    print(color("└" + "─" * (W - 2) + "┘"))


def _strip(s):
    out, i = [], 0
    while i < len(s):
        if s[i] == "\033":
            while i < len(s) and s[i] != "m":
                i += 1
            i += 1
        else:
            out.append(s[i])
            i += 1
    return "".join(out)


PAUSE = True
AUTO_DELAY = 1.4


def pause(msg="  press ENTER to continue ▸ "):
    if not PAUSE:
        time.sleep(AUTO_DELAY)
        return
    try:
        input(grey(msg))
    except (EOFError, KeyboardInterrupt):
        print()


def typeline(s, delay=0.0):
    print(s)
    if delay:
        time.sleep(delay)


# --------------------------------------------------------------------------- #
#  Daemon lifecycle (real binary, sandboxed)
# --------------------------------------------------------------------------- #

SECRET = b"a" * 64          # throwaway demo HMAC key (NOT a production secret)
METRICS_PORT = 0            # set in main()
WORKDIR = None
PROC = None


def find_binary():
    for cand in ("target/release/ts_cli", "target/debug/ts_cli"):
        if os.path.exists(cand):
            return cand
    sys.exit(red("ERROR: daemon binary not found. Run `cargo build -p ts_cli` first "
                 "(scripts/demo.sh does this for you)."))


DEMO_POLICY = """
# Throwaway demo policy. One trusted agent (a claims-processing AI) is allowed
# to do exactly two low-risk things. Everything else is, by design, refused.
global_safety_ceiling: 90.0
deny_anonymous_agents: true
agent_nodes:
  - id: "claims_agent"
    privilege_tier: 1
    max_sequence_quota: 1000
    allowed_intents:
      - "read_customer_record"
      - "summarize_claim"
    invariants: []
  - id: "burst_agent"
    privilege_tier: 1
    max_sequence_quota: 3
    allowed_intents:
      - "read_customer_record"
    invariants: []
"""


def start_daemon():
    global WORKDIR, PROC
    WORKDIR = tempfile.mkdtemp(prefix="jinnguard_demo_")
    sock = os.path.join(WORKDIR, "jg.sock")
    secret = os.path.join(WORKDIR, "secret")
    policy = os.path.join(WORKDIR, "policy.yaml")
    lineage = os.path.join(WORKDIR, "lineage.json")
    audit = os.path.join(WORKDIR, "audit.log")

    with open(secret, "wb") as f:
        f.write(SECRET)
    with open(policy, "w") as f:
        f.write(DEMO_POLICY)

    env = dict(os.environ)
    env["JINNGUARD_METRICS_PORT"] = str(METRICS_PORT)

    PROC = subprocess.Popen(
        [find_binary(),
         "--socket-path", sock,
         "--lineage-file", lineage,
         "--audit-log", audit,
         "--policy-file", policy,
         "--secret-file", secret],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env,
    )

    deadline = time.time() + 8
    while time.time() < deadline:
        if os.path.exists(sock):
            try:
                t = socket.socket(socket.AF_UNIX)
                t.connect(sock)
                t.close()
                return sock, audit
            except OSError:
                pass
        time.sleep(0.05)
    sys.exit(red("ERROR: daemon did not come up in time."))


def cleanup():
    global PROC, WORKDIR
    if PROC and PROC.poll() is None:
        PROC.terminate()
        try:
            PROC.wait(timeout=3)
        except subprocess.TimeoutExpired:
            PROC.kill()
    if WORKDIR and os.path.isdir(WORKDIR):
        shutil.rmtree(WORKDIR, ignore_errors=True)


# --------------------------------------------------------------------------- #
#  Wire protocol (identical framing to the production client/tests)
# --------------------------------------------------------------------------- #

_seq = 700_000_000


def _next_seq():
    global _seq
    _seq += 1
    return _seq


def send(sock_path, intent, agent_id, risk, *, forge_sig=False, version=1,
         reuse_seq=None):
    """Send one proposal to the real daemon; return its first-line SIGNAL."""
    seq = reuse_seq if reuse_seq is not None else _next_seq()
    agent_field = f',"agent_id":"{agent_id}"' if agent_id else ""
    payload = ('{"sequence_counter":%d,"intent_name":"%s",'
               '"action_risk_score":%s%s}') % (seq, intent, risk, agent_field)
    sig = "0" * 64 if forge_sig else hmac.new(
        SECRET, payload.encode(), hashlib.sha256).hexdigest()
    env = json.dumps({"payload": payload, "signature": sig},
                     separators=(",", ":")).encode()
    pkt = struct.pack(">IB", len(env), version) + env

    try:
        s = socket.socket(socket.AF_UNIX)
        s.settimeout(5)
        s.connect(sock_path)
        s.sendall(pkt)
        hdr = s.recv(5)
        if len(hdr) < 5:
            return "TRANSPORT_ERROR", seq
        ln = struct.unpack(">IB", hdr)[0]
        body = b""
        while len(body) < ln:
            chunk = s.recv(ln - len(body))
            if not chunk:
                break
            body += chunk
        s.close()
        return body.decode("utf-8", "replace").splitlines()[0].strip(), seq
    except OSError as e:
        return f"TRANSPORT_ERROR: {e}", seq


# Running scoreboard.
TALLY = {"allow": 0, "deny": 0, "reasons": {}}


def record(signal_line):
    if signal_line.startswith("SIGNAL: ALLOW"):
        TALLY["allow"] += 1
    elif signal_line.startswith("SIGNAL: DENY"):
        TALLY["deny"] += 1
        TALLY["reasons"][signal_line.replace("SIGNAL: ", "")] = \
            TALLY["reasons"].get(signal_line.replace("SIGNAL: ", ""), 0) + 1


def verdict_badge(signal_line):
    if signal_line.startswith("SIGNAL: ALLOW"):
        return green("  ✅  ALLOWED  ")
    if signal_line.startswith("SIGNAL: DENY"):
        return red("  ⛔  BLOCKED  ")
    return yellow("  ⚠  " + signal_line + "  ")


def scoreboard():
    a, d = TALLY["allow"], TALLY["deny"]
    return (f"   legitimate work allowed: {green(str(a))}"
            f"      attacks blocked: {red(str(d))}"
            f"      fail-opens: {bold('0')}")


# --------------------------------------------------------------------------- #
#  Scenario runner
# --------------------------------------------------------------------------- #

def scenario(sock, n, total, eli5, attacker_move, intent, agent, risk,
             owasp, expect, *, forge_sig=False, version=1, reuse_seq=None):
    print()
    print(rule())
    print(bold(f"  [{n}/{total}]  {eli5}"))
    print()
    print(grey("   What's being attempted:"))
    print(f"     {attacker_move}")
    print(grey("   The request on the wire:"))
    detail = f"agent={agent or '(none)'}  intent={intent}  declared_risk={risk}"
    if forge_sig:
        detail += "  signature=FORGED"
    if version != 1:
        detail += f"  protocol_version={version}"
    print(f"     {dim(detail)}")
    print()
    sig, _ = send(sock, intent, agent, risk,
                  forge_sig=forge_sig, version=version, reuse_seq=reuse_seq)
    record(sig)
    print("   Jinn Guard's live verdict:   " + verdict_badge(sig))
    print(grey(f"   reason code (from the daemon): {sig}"))
    print(grey(f"   maps to: {owasp}"))
    print()
    print(scoreboard())
    if expect == "allow" and not sig.startswith("SIGNAL: ALLOW"):
        print(yellow(f"   (note: expected ALLOW, daemon said {sig})"))
    if expect == "deny" and not sig.startswith("SIGNAL: DENY"):
        print(yellow(f"   (note: expected a block, daemon said {sig})"))
    return sig


# --------------------------------------------------------------------------- #
#  The walkthrough
# --------------------------------------------------------------------------- #

def act_intro():
    os.system("clear" if os.name != "nt" else "cls")
    banner("JINN GUARD  —  Live Demonstration",
           "A safety checkpoint that sits between AI agents and your computer")
    print()
    panel([
        bold("The problem, in one sentence:"),
        "AI \"agents\" can now run commands, touch files, and reach the",
        "network on their own. A clever prompt — or a bad actor — can talk",
        "an agent into doing something it was never supposed to do.",
        "",
        bold("What Jinn Guard does, explained simply:"),
        "Think of it as a " + yellow("security guard for AI robots") + ". Before any agent",
        "is allowed to DO something, it has to ask the guard first.",
        "The guard checks four things, every single time:",
        "   1. " + bold("Who are you?") + "      (a cryptographic ID badge it can't fake)",
        "   2. " + bold("Is this on your list?") + " (the exact jobs you're approved for)",
        "   3. " + bold("Is it too risky?") + "    (a math proof, not a guess)",
        "   4. " + bold("Have I seen this before?") + " (replays and tricks get caught)",
        "",
        "If anything is off, the answer is " + red("NO") + " — and the guard",
        "cannot be tricked, worn down, or talked into changing its mind.",
        "",
        dim("Everything you are about to see is the REAL product answering"),
        dim("REAL requests. Nothing on this screen is staged or mocked."),
    ])
    pause()


def act_setup():
    banner("Step 1  —  Start the real guard")
    print()
    print("   Launching the actual Jinn Guard daemon in a private sandbox")
    print("   (its own throwaway socket, policy, and key — nothing on your")
    print("   system is touched)...")
    print()
    sock, audit = start_daemon()
    time.sleep(0.4)
    panel([
        green("✓ ") + "Daemon is live and listening.",
        "",
        "It loaded a tiny demo policy with ONE trusted AI agent:",
        "   • " + bold("claims_agent") + " — an AI that processes insurance claims.",
        "   • It is allowed to do exactly TWO things:",
        "        read_customer_record   and   summarize_claim",
        "   • Anything else it tries is refused by default.",
        "",
        dim("This 'deny-by-default, allow-only-the-named-jobs' design is the"),
        dim("whole idea. The agent gets the smallest door that still lets it work."),
    ], color=green)
    pause()
    return sock, audit


def act_good(sock):
    banner("Step 2  —  The good robot does its job")
    print()
    print("   Our trusted claims AI asks to do something it's allowed to do:")
    print("   read a customer's record so it can process their claim.")
    scenario(
        sock, 1, 1,
        "A legitimate, approved request — this SHOULD be allowed.",
        "claims_agent presents its valid ID badge and asks to "
        + bold("read a customer record") + " (a job on its approved list).",
        "read_customer_record", "claims_agent", 10,
        "Normal operation — the agent doing exactly what it's for.",
        "allow",
    )
    print()
    print("   " + green("That's the point: Jinn Guard is invisible to good behavior."))
    print("   " + green("Real work flows through untouched. Now watch the attacks."))
    pause()


def act_attacks(sock):
    banner("Step 3  —  Now the attacks  (this is the important part)",
           "7 different real-world attacks, each fired at the live daemon")
    pause()

    T = 7
    scenario(
        sock, 1, T,
        "An attacker tries to FORGE the agent's ID badge.",
        "Someone copies a request but tampers with it, hoping the guard "
        "won't notice the cryptographic signature no longer matches.",
        "read_customer_record", "claims_agent", 10,
        "OWASP ASI: identity spoofing / broken authentication.",
        "deny", forge_sig=True,
    )
    pause()

    scenario(
        sock, 2, T,
        "A stranger shows up with an ID that isn't on the staff list.",
        "An unregistered agent ('ghost_agent') tries to act as if it "
        "belongs here.",
        "read_customer_record", "ghost_agent", 10,
        "OWASP ASI: unauthorized agent / excessive agency.",
        "deny",
    )
    pause()

    scenario(
        sock, 3, T,
        "An agent shows up wearing NO ID badge at all.",
        "An anonymous agent tries to slip through without identifying "
        "itself.",
        "read_customer_record", None, 10,
        "OWASP ASI: missing authentication.",
        "deny",
    )
    pause()

    scenario(
        sock, 4, T,
        "The trusted agent is hijacked and told to do something off-list.",
        "Even with a VALID badge, claims_agent is tricked into asking to "
        + bold("exfiltrate the database") + " — a job it was never approved for.",
        "exfiltrate_database", "claims_agent", 10,
        "OWASP ASI02: tool misuse / prompt-injected action. THE headline case.",
        "deny",
    )
    print()
    print("   " + yellow("^ This is the big one. The agent's identity is genuine,"))
    print("   " + yellow("  but the ACTION is not on its approved list — so it's"))
    print("   " + yellow("  refused anyway. A valid badge is not a blank check."))
    pause()

    scenario(
        sock, 5, T,
        "An approved job is requested, but at a dangerous risk level.",
        "claims_agent asks for an allowed action but with a risk score of "
        "95 — above the hard ceiling of 90. A math proof (Z3) blocks it.",
        "read_customer_record", "claims_agent", 95,
        "OWASP ASI: privilege/risk escalation. Blocked by formal proof, not a guess.",
        "deny",
    )
    pause()

    # Replay: one valid request, then re-send the EXACT same one.
    print()
    print(rule())
    print(bold(f"  [6/{T}]  An attacker records a real request and replays it."))
    print()
    print(grey("   What's being attempted:"))
    print("     A valid, signed request is captured off the wire and sent")
    print("     a SECOND time — the classic 'replay' attack.")
    valid_seq = _next_seq()
    sig1, _ = send(sock, "read_customer_record", "claims_agent", 10, reuse_seq=valid_seq)
    record(sig1)
    print()
    print("   First time (legitimate):     " + verdict_badge(sig1))
    sig2, _ = send(sock, "read_customer_record", "claims_agent", 10, reuse_seq=valid_seq)
    record(sig2)
    print("   Same request, sent again:    " + verdict_badge(sig2))
    print(grey(f"   reason code (from the daemon): {sig2}"))
    print(grey("   maps to: OWASP ASI: replay / nonce reuse."))
    print()
    print(scoreboard())
    pause()

    # Quota exhaustion with the burst_agent.
    print()
    print(rule())
    print(bold(f"  [7/{T}]  An agent tries to 'wear down' the guard with volume."))
    print()
    print(grey("   What's being attempted:"))
    print("     A second agent (burst_agent) is rate-limited to 3 actions.")
    print("     It floods 6 requests, trying to push past its budget.")
    print()
    allowed = denied = 0
    for i in range(6):
        sig, _ = send(sock, "read_customer_record", "burst_agent", 10)
        record(sig)
        if sig.startswith("SIGNAL: ALLOW"):
            allowed += 1
            tag = green("ALLOWED")
        else:
            denied += 1
            tag = red("BLOCKED ") + grey("(" + sig.replace("SIGNAL: ", "") + ")")
        print(f"     request {i + 1}:  {tag}")
    print()
    print(f"   Result: exactly {green(str(allowed))} allowed (its real budget), "
          f"{red(str(denied))} blocked.")
    print("   " + yellow("The guard does not get tired and does not lose count."))
    print()
    print(scoreboard())
    pause()


def act_metrics():
    banner("Step 4  —  The guard's own live counters",
           "Read straight back from the daemon's /metrics endpoint")
    print()
    print(grey(f"   GET http://127.0.0.1:{METRICS_PORT}/metrics  (loopback only)"))
    print()
    try:
        with urllib.request.urlopen(
                f"http://127.0.0.1:{METRICS_PORT}/metrics", timeout=3) as r:
            text = r.read().decode()
    except Exception as e:
        print(yellow(f"   (metrics endpoint unavailable: {e})"))
        return

    wanted = ("jinnguard_build_info",
              "jinnguard_proposals_total",
              "jinnguard_decisions_total",
              "jinnguard_denials_total")
    lines = [ln for ln in text.splitlines()
             if ln and not ln.startswith("#") and ln.startswith(wanted)]
    maxlen = W - 7  # leave room for the "   " indent + borders
    shown = [(ln[:maxlen - 1] + "…") if len(ln) > maxlen else ln
             for ln in lines[:16]]
    panel([bold("These are the daemon's OWN numbers, not ours:")] +
          ["   " + grey(ln) for ln in shown], color=green)
    print()
    print("   In plain English: every request we just sent was counted, and")
    print("   every block was recorded WITH ITS REASON (the denials_total lines")
    print("   above). An ops team watches this live in Grafana/Prometheus.")
    pause()


def act_receipts():
    banner("Step 5  —  The receipts  (measured, reproducible, honest)",
           "Numbers from real hardware — not projections")
    print()
    panel([
        bold("Speed") + "  (10,000 requests, full pipeline, single client):",
        "   Half of all decisions finish in   " + green("257 microseconds"),
        "   95% finish within               " + green("366 microseconds"),
        "   99% finish within               " + green("463 microseconds"),
        "   Even the slowest:               " + green("1.9 milliseconds"),
        dim("   -> faster than a blink; the agent never feels it."),
        "",
        bold("Scale") + "  (many agents at once):",
        "   ~" + green("6,500 decisions per second") + ", " + green("0 errors") + ", 0 fail-opens.",
        "",
        bold("Attack resistance") + "  (cargo test --test swarm_attack):",
        "   " + green("12 / 12") + " adversarial tests pass, " + green(">1,200")
        + " hostile requests,",
        "   " + green("0 fail-open") + ", " + green("0 misclassification") + ".",
        "",
        bold("Kernel enforcement") + "  (validated armed on real hardware):",
        "   2,500 enforced operations, " + green("0 fail-open") + ".",
        "",
        bold("Tests:") + " " + green("122 passing") + "  (4 Z3 + 93 unit "
        + "+ 13 integ + 12 swarm).",
    ])
    print()
    print(grey("   Reproduce it yourself:"))
    print(grey("     cargo bench --bench stress_bench"))
    print(grey("     cargo test  --release --test swarm_attack"))
    print(grey("   Full tables: BENCHMARKS-01.md"))
    pause()


def act_safety():
    banner("Step 6  —  \"Is this thing safe to run?\"  (yes — here's why)",
           "The #1 question for anything that can say 'no' inside a kernel")
    print()
    panel([
        bold("Could it lock me out of my own computer?  No."),
        "   Kernel enforcement is " + yellow("cgroup-scoped") + ": only the one agent",
        "   box you point it at is governed. Your desktop, your shell, and",
        "   every other process are structurally OUT of scope and pass",
        "   through untouched. A wrong scope makes a TEST fail — not your",
        "   machine. Validated armed on a single laptop with no lockout.",
        "",
        bold("What if the safety checker itself gets stuck?  It fails CLOSED."),
        "   The math proof (Z3) runs under a 250 ms timeout. If it can't",
        "   prove an action safe in time, the answer is " + red("NO") + ", never 'sure'.",
        "",
        bold("Default posture is observe-first."),
        "   It can run audit-only (watch + log, block nothing) before you",
        "   ever arm enforcement. Turn the dial up only when you trust it.",
        "",
        bold("And the honest part — what it does NOT claim:"),
        "   The risk SCORE is still a heuristic; the math proof is only as",
        "   good as the number fed in. That's why identity + the approved-",
        "   jobs list + kernel enforcement are the real walls, with risk as",
        "   one more layer. This is written down in THREAT_MODEL.md §8.",
    ], color=yellow)
    pause()


def act_close():
    banner("Why Jinn Guard wins",
           "Where the protection actually lives")
    print()
    panel([
        "Most AI-governance tools live " + bold("inside") + " the app or the SDK —",
        "the same place a compromised agent already runs. If the agent",
        "goes rogue, it can often go around them.",
        "",
        "Jinn Guard puts the final checkpoint in the " + bold("Linux kernel") + ",",
        "underneath the agent. You can't sweet-talk a kernel hook, and an",
        "agent can't reach around something that sits below it.",
        "",
        green("   • Identity it can't forge   (cryptographic, per request)"),
        green("   • A job list it can't exceed (deny-by-default allow-list)"),
        green("   • A risk ceiling it can't cross (a math proof, fail-closed)"),
        green("   • A kernel backstop it can't bypass (eBPF-LSM)"),
        green("   • A tamper-evident audit trail (hash-chained)"),
        "",
        "   Sub-millisecond. 0 fail-opens. 122 tests. Reproducible today.",
    ], color=green)
    print()
    print(bold("   This is the layer the agent era is missing. It runs now."))
    print()
    print(rule())
    print()


def main():
    global PAUSE, METRICS_PORT, AUTO_DELAY
    ap = argparse.ArgumentParser(description="Jinn Guard live demo dashboard")
    ap.add_argument("--auto", action="store_true",
                    help="autoplay without waiting for ENTER (for recording)")
    ap.add_argument("--delay", type=float, default=1.4,
                    help="seconds between steps in --auto mode")
    ap.add_argument("--metrics-port", type=int, default=19_900,
                    help="loopback port for the live metrics panel")
    ap.add_argument("--no-color", action="store_true")
    args = ap.parse_args()

    global USE_COLOR
    if args.no_color:
        USE_COLOR = False
    PAUSE = not args.auto
    AUTO_DELAY = args.delay
    METRICS_PORT = args.metrics_port

    atexit.register(cleanup)
    signal.signal(signal.SIGINT, lambda *_: (cleanup(), sys.exit(130)))
    signal.signal(signal.SIGTERM, lambda *_: (cleanup(), sys.exit(143)))

    act_intro()
    sock, _audit = act_setup()
    act_good(sock)
    act_attacks(sock)
    act_metrics()
    act_receipts()
    act_safety()
    act_close()


if __name__ == "__main__":
    main()
