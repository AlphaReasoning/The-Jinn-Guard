# Cover note (reviewer / professor)

A short note to accompany the reviewer package (`jinn-guard-v1.0-review.tar.gz`).
Replace the bracketed placeholders before sending.

---

**Subject: Jinn Guard — prototype for your review (one-command validation included)**

Dr. [Last name],

Thank you for offering to look at this. Attached is **Jinn Guard**
(`jinn-guard-v1.0-review.tar.gz`), the project I've been building: a
kernel-anchored governance firewall that treats an autonomous AI agent as an
untrusted process and mediates its actions — process execution, network,
filesystem, and tool calls — at the operating-system boundary using eBPF-LSM
kernel hooks, a Rust policy daemon, and a Z3 invariant layer.

Everything is verifiable in one command. After extracting the archive:

```
bash scripts/run_professor_validation.sh            # build + full test suite + Docker mediation
sudo bash scripts/run_professor_validation.sh       # adds the kernel layer in audit-only mode (blocks nothing)
sudo bash scripts/run_professor_validation.sh --arm # adds real kernel allow/deny enforcement
```

The script detects your machine's capabilities and prints a PASS/SKIP/FAIL
summary. A couple of notes:

- **It's safe to run, including `--arm`.** Kernel enforcement is confined to a
  dedicated cgroup the test creates, so the rest of the machine — your own
  session included — is never affected, and a hard 10-minute watchdog plus a
  reboot clear all state. I validated this on my own laptop with no lockout.
- **Requirements:** Tiers 1–2 need only the Rust toolchain (rustup) and, for the
  Docker mediation tier, Docker. Tiers 3–4 need Linux 5.16+ with BPF-LSM enabled
  (boot parameter `lsm=...,bpf`), plus `clang` and `bpftool`
  (`apt install clang bpftool libbpf-dev`); Tier 4 additionally needs cgroup v2,
  which is the default on modern Linux.
- **Honest scope:** this is a validated research prototype / controlled-pilot
  MVP, **not** an independently audited production product, and it's been
  validated on Debian/Linux 6.12 only. `PROFESSOR_VALIDATION.md` explains each
  check, and `THREAT_MODEL.md` lays out the security model, what's mitigated, and
  the disclosed limitations.

The headline result: armed kernel enforcement across execution, network, and
filesystem ran 2,500 operations with zero fail-open and zero incorrect decisions.

I'd genuinely value your feedback on the approach and on anything you'd want to
see hardened next. Happy to walk through any part of it.

Thank you,
Cassey Snider
