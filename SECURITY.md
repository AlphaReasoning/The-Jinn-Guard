# Security Policy

Jinn Guard is a kernel-level enforcement security tool and a **validated research
prototype**. We take security reports seriously and welcome good-faith research —
including attempts to break the enforcement guarantees.

## Reporting a vulnerability

**Please report privately first.** Do not open a public issue for a security
vulnerability.

- **Preferred:** open a private report via GitHub Security Advisories →
  [Report a vulnerability](https://github.com/AlphaReasoning/The-Jinn-Guard/security/advisories/new)
- **Email:** `security@alpha-reasoning.org` *(update to your monitored address)*

Please include: affected version/commit, environment (distro + kernel), a
description of the issue and its impact, and reproduction steps or a proof of
concept. If you have a suggested fix, even better.

We aim to acknowledge a report within **3 business days** and to provide an initial
assessment within **10 business days**. Timelines are best-effort for a
prototype maintained by a small team.

## Coordinated disclosure

We follow coordinated disclosure. We ask that you give us a reasonable window
(typically up to **90 days**) to investigate and remediate before any public
disclosure, and we will keep you informed of progress. We are happy to credit
reporters in the advisory unless you prefer to remain anonymous.

## Scope

In scope:
- The `ts_cli` governance daemon and its wire protocol (the 5-byte framed UDS
  protocol and the HMAC-signed envelope).
- The BPF-LSM enforcement programs under `bpf/`.
- Identity (`SO_PEERCRED` + HMAC), anti-replay, quota, risk-ceiling, and policy
  enforcement logic.
- The tamper-evident audit log and its hash chain.
- Anti-lockout / fail-closed behavior (a way to brick a host or fail open is a
  high-severity finding).

Out of scope:
- The private control-plane / fleet components (not in this repository).
- Findings that require root on the host *and* are outside the daemon's stated
  threat model (the host root is trusted).
- Issues in third-party dependencies that are not exploitable through Jinn Guard.
- The intentionally-vendored example/test corpora.

We are *especially* interested in: bypasses of the kernel enforcement floor,
TOCTOU between the userspace verdict and the syscall, defeats of the
`SO_PEERCRED` + HMAC identity binding, and ways to defeat the cgroup-scoped LSM
enforcement. See [`THREAT_MODEL.md`](THREAT_MODEL.md).

## A note on advisory identifiers

Findings tracked in this repository use **internal, self-issued** identifiers of
the form `JG-ADV-YYYY-NNN`. **These are not CVEs** and are not issued by a CNA.
See [`SECURITY/ADVISORIES.md`](SECURITY/ADVISORIES.md) for the registry. If a
finding warrants a CVE, we will pursue one through the appropriate channel.

## Safe harbor

We consider good-faith security research conducted in line with this policy to be
authorized. We will not pursue or support legal action against researchers who:
act in good faith, avoid privacy violations and service disruption, only interact
with systems/accounts they own or have permission to test, and give us a
reasonable chance to remediate before public disclosure. If in doubt, ask first.
