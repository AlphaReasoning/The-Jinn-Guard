# Jinn Guard Break-It Challenge

Jinn Guard is ready for external, good-faith attempts to break the public
open-core enforcement stack. This challenge is an invitation to test the claims
in this repository, find concrete weaknesses, and report them privately first.

This is not a bug bounty program. There is no promised payment. Valid reports
may receive public credit in an advisory or release note if the reporter wants
credit.

## Scope

In scope:

- The public repository at `AlphaReasoning/The-Jinn-Guard`.
- The `ts_cli` governance daemon and its Unix-domain-socket wire protocol.
- The MCP gateway code in this repository.
- The `ts_wire` decoder, signed envelope, HMAC verification, replay defense, and
  frame parsing.
- Policy enforcement paths: identity, lineage, quota, risk ceiling, Z3 invariant
  checks, audit logging, metrics, and explanation output.
- The BPF-LSM programs under `bpf/lsm/`, including cgroup scoping, exec, socket,
  and filesystem enforcement.
- Tests, validation scripts, CI behavior, and public documentation claims.

Out of scope:

- The private control-plane server, fleet operations tooling, `gtm/`, `paper/`,
  `INTEGRATION.md`, `ARTICLE-*`, or any private repository material.
- GitHub Actions infrastructure, self-hosted runners, Azure VMs, maintainer
  accounts, email systems, DNS, package registries, or any third-party service.
- Social engineering, phishing, credential attacks, or attempts to access secrets.
- Denial-of-service against systems you do not own or have explicit permission
  to test.
- Findings in third-party dependencies unless they are exploitable through a
  Jinn Guard entry point.
- Attacks that require host root and do not cross a stated Jinn Guard trust
  boundary. Host root is outside the threat model.

## High-Value Targets

We are most interested in reports that show one of these outcomes:

- Kernel enforcement fail-open for a governed cgroup.
- Operator lockout or enforcement outside the governed scope.
- A userspace ALLOW for a request that should be denied by policy.
- A direct syscall path that bypasses the BPF-LSM floor.
- A replay, lineage, quota, or identity bypass.
- HMAC-authenticated `agent_id` confusion across OS users.
- A way to forge, truncate, reorder, or hide audit entries without detection.
- A parser or gateway input that crashes the daemon, exhausts resources, or
  causes request smuggling.
- A mismatch between documented security claims and reproducible behavior.

## Rules of Engagement

- Test only systems you own or have written authorization to test.
- Prefer local reproduction using this repository's tests, scripts, and demo
  harnesses.
- Do not target the private control plane or any infrastructure outside this
  public repository.
- Do not publish exploit details before coordinated disclosure is complete.
- Keep proofs of concept minimal. Demonstrate the issue without persistence,
  lateral movement, credential collection, or data destruction.
- Stop and report if you unexpectedly reach data, secrets, or infrastructure
  outside the challenge scope.

Good-faith work inside these rules is covered by the safe harbor in
[`SECURITY.md`](SECURITY.md).

## Suggested Starting Points

Run the public validation harness first:

```bash
python3 scripts/validate/validate.py
cargo test --release --test swarm_attack
cargo test -p ts_cli --bin ts_cli
cargo test -p ts_checker
```

For kernel work, use the ignored real-kernel tests only on machines where you
can safely load BPF-LSM programs and recover the host:

```bash
cargo test -p ts_cli --features enterprise --test kernel_lsm -- --ignored
```

Review the model before filing:

- [`SECURITY.md`](SECURITY.md) - disclosure policy, safe harbor, scope.
- [`THREAT_MODEL.md`](THREAT_MODEL.md) - trusted boundaries and residual risks.
- [`SECURITY_ARCHITECTURE.md`](SECURITY_ARCHITECTURE.md) - component and data
  flow view.
- [`RED_TEAM_FINDINGS.md`](RED_TEAM_FINDINGS.md) - internal red-team findings
  already fixed or documented.

## Report Template

Please report privately first through GitHub Security Advisories:

<https://github.com/AlphaReasoning/The-Jinn-Guard/security/advisories/new>

Include:

- Affected commit, branch, or release.
- Host environment: distro, kernel version, architecture, and whether BPF-LSM was
  enabled.
- Exact policy, environment variables, and commands used.
- Expected decision and observed decision.
- Minimal proof of concept or test patch.
- Impact assessment: what security goal is broken and what privilege the attacker
  needs.
- Any logs, audit entries, metrics, or kernel output needed to reproduce.

If the finding is accepted, we will track it using the repository's internal
`JG-ADV-YYYY-NNN` advisory format unless an external CVE is warranted.
