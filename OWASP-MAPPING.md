# Jinn Guard — OWASP Top 10 for Agentic Applications (2026) Coverage Mapping

**Standard:** OWASP Top 10 for Agentic Applications, 2026 edition (`ASI01–ASI10`),
published by the OWASP GenAI Security Project, 2025-12-09.
**Mapped:** 2026-06-12.

> **This is a self-assessed control-coverage mapping, not a certification.** OWASP
> does not certify products. The OWASP GenAI project publishes a threat taxonomy;
> this document maps Jinn Guard's controls against it and states, honestly, where
> coverage is strong, partial (containment only), or out of scope.

## How to read the coverage column

- **Strong** — Jinn Guard directly prevents or enforces against this threat class.
- **Partial / containment** — Jinn Guard does not prevent the root cause, but
  structurally bounds the blast radius (a compromised/hijacked agent still cannot
  act outside policy).
- **Out of scope** — this is a model-, data-, or human-layer threat that a
  kernel-anchored action firewall does not address. Stated plainly rather than
  overclaimed.

Jinn Guard operates at the **enforcement layer** (what an agent is allowed to *do*
to the OS), not the **cognition layer** (what an agent *thinks* or *retrieves*).
That boundary is the honest dividing line below.

---

## Coverage summary

| Level | Count | Items |
|---|---|---|
| **Strong** | 5 | ASI02, ASI03, ASI05, ASI07, ASI10 |
| **Partial / containment** | 3 | ASI01, ASI04, ASI08 |
| **Out of scope** | 2 | ASI06, ASI09 |

Jinn Guard covers the **enforcement-layer half** of the Top 10 strongly, contains
three more, and is deliberately silent on the two cognition/human-layer risks.

---

## Detailed mapping

### ASI01 — Agent Goal Hijack · **Partial / containment**
An attacker manipulates the agent's objectives or decision path.
Jinn Guard does not inspect prompts or protect the agent's reasoning, so it cannot
*prevent* a hijack. It does ensure a hijacked agent's **actions** still pass the
intent allowlist, quota, Z3 safety ceiling, and kernel enforcement — so the hijack
cannot translate into an out-of-policy action.
*Evidence:* intent gate + Z3 ceiling (`ts_cli/src/main.rs` gate chain);
`THREAT_MODEL.md`.

### ASI02 — Tool Misuse and Exploitation · **Strong**
An agent uses connected tools/APIs unsafely or beyond intent.
Deny-by-default intent allowlist; MCP gateway mediates tool calls; kernel LSM hooks
enforce file/socket/exec boundaries regardless of how the tool is invoked.
*Evidence:* intent allowlist gate; `ts_cli/src/mcp_gateway.rs`; LSM hooks
(`bpf/lsm/*.c`); attack tests `test_intent_injection_flood`,
`test_path_traversal_mcp` (`ts_cli/tests/swarm_attack.rs`).

### ASI03 — Identity and Privilege Abuse · **Strong**
Agents misuse credentials or inherited permissions to exceed limits.
Every action is authenticated with HMAC-SHA256; unknown and anonymous agents are
denied; the daemon can drop dangerous Linux capabilities (`JINNGUARD_HARDEN_CAPS`);
kernel enforcement is cgroup-scoped.
*Evidence:* HMAC verify + agent-ID gate; capability hardening module
(`ts_cli/src/main.rs`); attack tests `test_hmac_forgery_flood`,
`test_unknown_agent_id_flood`, `test_anonymous_agent_flood`.

### ASI04 — Agentic Supply Chain Vulnerabilities · **Partial / containment**
Risk from third-party tools, plugins, MCP servers, or external components.
Jinn Guard does not vet the provenance of tools/plugins, so it does not *prevent* a
compromised component. It does mediate MCP traffic and constrain what any tool can
do via intent/policy/kernel enforcement, limiting the damage a malicious component
can cause.
*Evidence:* `ts_cli/src/mcp_gateway.rs`; intent/policy gates; `THREAT_MODEL.md`
(trust boundaries).

### ASI05 — Unexpected Code Execution (RCE) · **Strong**
An agent generates, modifies, or runs code/commands unsafely.
The kernel `bprm_check_security` LSM hook denies execution of non-allowlisted
binaries for governed agents, with interpreter-chain mitigation
(JG-ADV-2026-001, `DENY_INTERPRETER_NOT_ALLOWED`). Enforcement is in the kernel and
cannot be bypassed by the agent process.
*Evidence:* `bpf/lsm/jg_bprm_check_security.c`; `CHANGELOG.md` (JG-ADV-2026-001);
Tier-4 armed validation.

### ASI06 — Memory and Context Poisoning · **Out of scope**
Corruption of agent memory systems or RAG databases.
This is a data/cognition-layer threat. Jinn Guard does not read, store, or validate
agent memory or retrieval context and makes no claim here.
*Evidence:* n/a (declared gap; see `THREAT_MODEL.md` §residual risks).

### ASI07 — Insecure Inter-Agent Communication · **Strong**
Spoofing or tampering in agent message channels.
Every governed action is carried in an HMAC-SHA256 `SignedEnvelope` with replay
protection (monotonic sequence + lineage), so messages cannot be forged, tampered,
or replayed. (Scope: this secures the governed action channel and proposals; it
does not itself encrypt arbitrary application-level agent-to-agent traffic.)
*Evidence:* `SignedEnvelope` verify path; replay gate; attack tests
`test_replay_storm`, `test_delegation_chain_forgery`.

### ASI08 — Cascading Failures · **Partial / containment**
Small errors propagate across planning, execution, and memory.
Jinn Guard does not address logical cascade in agent planning, but per-agent
quotas, the hard Z3 risk ceiling, and the monotonic tighten-only adaptive floor
bound runaway action volume and escalation, limiting resource/blast-radius cascade.
*Evidence:* quota gate; adaptive floor (`adaptive_floor_tests`); attack test
`test_quota_exhaustion_race`.

### ASI09 — Human-Agent Trust Exploitation · **Out of scope**
Users over-trust agent recommendations (social engineering).
This is a human/UX-layer threat. Marginal indirect benefit: the hash-chained,
tamper-evident audit log gives humans an independent ground truth to verify what an
agent actually did — but Jinn Guard does not govern the human in the loop.
*Evidence:* hash-chained audit log (indirect only).

### ASI10 — Rogue Agents · **Strong**
A compromised agent acts harmfully while appearing legitimate.
Per-agent identity, deny-by-default for unknown/anonymous agents, per-agent quotas,
and cgroup-scoped kernel enforcement bound what any single agent can do even if it
turns rogue; the tamper-evident audit trail records every action for detection.
*Evidence:* identity/quota gates; kernel cgroup scope (`bpf/lsm/jg_common.h`);
attack tests `test_concurrent_mixed_attack`, `test_daemon_resilience_after_swarm`.

---

## Honest scope statement

Jinn Guard is a **kernel-anchored enforcement layer**. It maps strongly to the
OWASP Agentic risks that concern an agent's **actions on the operating system**
(ASI02, ASI03, ASI05, ASI07, ASI10), provides **containment** for three more
(ASI01, ASI04, ASI08), and is **out of scope** for the model/memory and human-trust
risks (ASI06, ASI09), which require data-layer and HITL controls Jinn Guard does
not provide.

It is therefore best positioned as the **enforcement complement** to an
application-/model-layer governance stack — not a single-tool answer to the full
Top 10. Claims of "full OWASP Agentic Top 10 coverage" would be inaccurate for any
enforcement-only product, including this one.

**This mapping is self-assessed and not independently audited.** See
[`THREAT_MODEL.md`](THREAT_MODEL.md) for the security model and residual risks.

---

## Sources
- OWASP Top 10 for Agentic Applications for 2026 — OWASP GenAI Security Project:
  https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
- Announcement (2025-12-09):
  https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/
