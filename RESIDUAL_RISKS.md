# Residual Risk Register

This register is the short operator-facing summary of known residual risks after
the current hardening work. The authoritative adversary model and detailed
mitigation evidence remain in [`THREAT_MODEL.md`](THREAT_MODEL.md).

Jinn Guard is a validated research prototype / controlled-pilot MVP. This file
is intentionally conservative: it records what is still open, partially
mitigated, or out of scope so release notes and sales material do not overclaim.

| ID | Residual risk | Status | Current mitigation | Next action |
|---|---|---|---|---|
| RR-001 | No independent third-party security audit yet. | Open | Structured self-review, internal red-team batches, CI gates, and real-kernel validation evidence. | Commission scoped external review of BPF-LSM hooks, UDS auth, policy gates, audit chain, and release integrity. |
| RR-002 | Kernel and distro coverage is strong but not exhaustive. | Open | Validated on Debian 13 / 6.12, Ubuntu 24.04 / 6.17, and AlmaLinux 9 / 5.14 with SELinux Enforcing. | Broaden scheduled validation over more kernels, distro variants, and arm64. |
| RR-003 | Root-equivalent host adversary can bypass or remove enforcement. | Out of scope | Threat model explicitly excludes already-root attackers, kernel module loaders, and actors able to unload LSM/BPF state. | Keep deployment guidance clear; pair with host hardening, secure boot, least privilege, and immutable infra controls. |
| RR-004 | Per-agent cryptographic isolation is file-backed HMAC v1, not certificate-bound tenant identity. | Partially mitigated | `agent_nodes[].allowed_peer_uids` binds signed `agent_id` values to `SO_PEERCRED` UIDs; optional `--agent-secret-dir` requires a per-agent HMAC key for selected ids; shared-key rotation supports current/previous keys. | Add certificate-bound or fleet-distributed per-agent identities for mutually distrusting tenants. |
| RR-005 | DNS mediation is heuristic. | Partially mitigated | Kernel network hooks enforce IP allow/deny/default-deny policy; DNS payload inspection is best-effort for port-53 traffic. | Move domain policy to resolver/proxy integration or require egress through a governed DNS layer. |
| RR-006 | Policy-load-time inode pinning can miss a denied directory whose inode is replaced after policy load. | Partially mitigated | Denied directories are matched by `(s_dev, i_ino)`, preventing path-string remap bypasses; replacement requires privileged filesystem control and policy reload can re-resolve. | Re-resolve inode-backed deny policy on reload and document reload after filesystem/mount changes. |
| RR-007 | Interpreter chains remain an allowlist responsibility. | Partially mitigated | Governed agents with executable allowlists are denied known interpreters unless explicitly permitted. | Add eBPF-traced child-process attribution for interpreter-launched tools. |
| RR-008 | Semantic risk scoring still includes local heuristic classification. | Mitigated | Introduced `--heuristic-fallback-mode conservative` to clamp heuristic confidence and floor risk scores, treating unconfigured-scorer results as medium-risk for policy gating without creating an allow path. | Continually test heuristic and RootAI scoring against adversarial bypasses. |
| RR-009 | Confused-deputy protection denies and detects known control sockets, but does not govern every possible deputy action. | Partially mitigated | Kernel AF_UNIX deny/default-deny allowlist plus deputy alerts cover known orchestrator sockets. | Continue caller-identity propagation work from [`DEPUTY_GOVERNANCE.md`](DEPUTY_GOVERNANCE.md). |
| RR-010 | Audit privacy controls need deployment-specific retention decisions. | Open | Hash-chain entries avoid raw PII where possible; erasable PII side table, pseudonym-salt rotation, and erasure helpers are implemented. | Define retention period, DPIA, and log shipping controls per deployment. |

## Release Claim Boundary

The current public claim should remain:

- "validated research prototype / controlled-pilot MVP"
- "not independently audited"
- "kernel-enforced for governed cgroups on validated kernels"
- "open-core public agent; private fleet control plane is not in this repo"

Do not claim enterprise GA or independent audit completion until RR-001 is
closed.
