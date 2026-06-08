# Jinn Guard / RootAI Convergence Architecture

Mission: Jinn Guard is a local trust and governance runtime that acts as a firewall for AI agents and multi-agent systems by verifying identity, lineage, intent, risk, and policy compliance before actions are executed.

## Executive Finding

The repository has a working local Unix socket enforcement daemon with HMAC envelope validation, SO_PEERCRED process binding, replay tracking, JSON policy loading, and a Z3 ceiling proof. It does not yet have production kernel telemetry, RootAI service integration, durable lineage storage, or topology-aware multi-agent governance. The highest-risk design flaw was that the daemon treated `action_risk_score` and `session_privilege_bit` as trusted client inputs. The current patch introduces daemon-derived governance abstractions and makes client-declared risk an upward-only signal.

## Current Module Review

| Module | Current role | Status | Recommendation | Why | Complexity | Security impact | Performance impact |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `ts_cli/src/main.rs` | Daemon, socket IPC, HMAC verification, peer PID extraction, policy check | Real critical path | Keep as execution broker, split into IPC, observation, risk, policy modules | It currently owns too many trust decisions in one file | M | High | Low to medium from clearer state handling |
| `ts_cli/src/governance.rs` | New trust model types and local semantic fallback | Added | Promote to a shared governance crate once APIs stabilize | Other agents and services need the same schemas | M | High | Low |
| `ts_checker/src/lib.rs` | Z3 policy proof | Real but narrow | Keep as policy verifier, change from scalar demo math to explicit policy obligations | Z3 should prove daemon-derived assertions, not client-provided risk deltas | M | High | Low to medium depending obligation count |
| `ts_cli/src/ebpf_monitor.rs` | Kernel telemetry placeholder | Replaced with explicit no-op source plus aya-rs roadmap probes | Implement aya userspace loader and eBPF programs | Current runtime only observes SO_PEERCRED and `/proc`; it cannot see exec/open/connect behavior | H | Very high | Medium if ring buffers are bounded |
| `ts_parser/src/lib.rs` | DSL parser | Incomplete | Keep only as topology DSL prototype or replace with RootAI parser outputs | It discards invariant expressions and maps all invariants to `ThreeBodyGravity` | M | Medium | Low |
| `ts_compiler/src/lib.rs` | Transpiler | Placeholder | Remove from enforcement path until it generates meaningful policy artifacts | It returns a hardcoded `ThreeBodyEngine` | L | Low now, medium if trusted later | Low |
| `jinnguard_py/jinnguard/client.py` | Python SDK | Patched | Keep as signed local IPC client; add typed proposal builder tests | It now matches the daemon envelope protocol | S | Medium | Low |
| `run_fabric_swarm.py` | Multi-agent demo | Partial | Convert to integration test with expected ALLOW, replay DENY, drift DENY | It is useful but not production governance | S | Medium | Low |
| `run_mock_agent.py` | Demo client | Was dead, now SDK supports it | Update to use stable SDK defaults and explicit intent names | Previously called an unexported `Guard` | S | Low | None |
| `policy.yaml` | Enterprise policy sketch | Dead config | Either load it or remove it from runtime claims | Daemon only loads `jinnguard_policy.json` | S | Medium | Low |
| `current_intent.ts`, `compiled_output.rs`, `session_ledger.json` | Generated/demo artifacts | Disconnected | Move under `examples/fixtures` | They are not consumed by daemon enforcement | S | Low | None |
| `run_three_body.sh` | Source rewrite demo | Dangerous/dead | Delete or quarantine under `examples/legacy` | It overwrites Rust source files | S | Medium | None |
| `jinn_browser_sentinel.sh` | Browser demo | Incomplete | Do not treat as enforcement; replace with brokered action request | It writes a DSL file, parses logs, and launches Firefox directly | M | High | Low |
| `README.md` performance claims | Documentation | Unverified in repo | Add benchmark harness or mark claims as historical | No benchmark source validates the stated p95 numbers | S | Medium credibility impact | None |

## Mocked, Placeholder, Incomplete, Duplicated, Or Dead Components

1. `ts_cli/src/ebpf_monitor.rs`: was a fake enforcement monitor; now an honest no-op telemetry source with aya-rs probe roadmap.
2. `ts_parser/src/lib.rs`: parser accepts a small DSL but throws away real invariant and transform expressions.
3. `ts_compiler/src/lib.rs`: hardcoded transpiler output, not suitable for policy or runtime generation.
4. `ts_checker::PolicyEngine::validate_sequence`: internal nonce cache is unused by the daemon; lineage replay now happens in the daemon.
5. `run_three_body.sh`: overwrites source files and embeds an obsolete checker implementation.
6. `run_pipeline.sh` and `jinn_browser_sentinel.sh`: duplicate DSL writing and do not feed policy decisions through the daemon.
7. `policy.yaml`: richer policy file not loaded by runtime.
8. `session_ledger.json`, `current_intent.ts`, `compiled_output.rs`: generated state or examples disconnected from enforcement.
9. `ts_cli` dependencies on parser/compiler crates: currently unused by the daemon path.
10. `tokio` dependency: not used by current synchronous thread-per-connection daemon.
11. Checked-in `target/`, `venv/`, release zip, and colon-suffixed files: build/environment artifacts should be removed from version control by a deliberate cleanup PR.

## Dependency Graphs

### Execution Path

```text
Agent SDK or local agent
  -> Unix socket /tmp/jinnguard.sock
  -> SignedEnvelope { payload, signature }
  -> HMAC verification with JINN_GUARD_SECRET
  -> SO_PEERCRED pid/uid/gid
  -> ObservationRecord from /proc
  -> ClientProposal parse
  -> SemanticIntent classification
  -> CapabilityProfile
  -> RiskAssessment
  -> AgentLineage replay and drift checks
  -> PolicyDecision
  -> Z3 ceiling proof
  -> SIGNAL: ALLOW or SIGNAL: DENY_*
```

### Policy Path

```text
jinnguard_policy.json
  -> PolicyConfig { upper_safety_boundary, minimum_trust_score }
  -> SIGHUP hot reload
  -> RiskAssessment.fused_risk and trust_score
  -> PolicyDecision
  -> ts_checker::PolicyEngine Z3 verification
  -> broker response
```

### Telemetry Path

```text
Current:
Unix socket peer credentials
  -> /proc/{pid}/exe, /proc/{pid}/cmdline, /proc/{pid}/ns/pid
  -> ObservationRecord
  -> CapabilityProfile and observed risk

Target:
aya-rs eBPF programs
  -> execve tracepoint
  -> openat tracepoint
  -> connect tracepoint
  -> capability transition tracepoint or kernel-hook fallback
  -> ring buffer
  -> Observation Layer event normalizer
  -> ObservationRecord stream
  -> TrustState update
```

### Semantic Analysis Path

```text
ClientProposal { intent_name, prompt, plan, source_code, requested_capabilities }
  -> RootAI semantic service over local UDS/gRPC
  -> parser registry, symbol extraction, taint analysis, plugin reports
  -> SemanticIntent { class, confidence, signals, risk_score }
  -> RiskAssessment
  -> PolicyDecision
```

## Module Diagram

```text
+-------------------+       +---------------------+
| Agent Runtime     |       | RootAI Semantic Svc |
| prompts/plans/src |       | parsers/plugins     |
+---------+---------+       +----------+----------+
          |                            |
          v                            v
+-------------------+       +---------------------+
| Execution Broker  +<------+ Semantic Analysis   |
| Unix socket IPC   |       | SemanticIntent      |
+---------+---------+       +----------+----------+
          |                            ^
          v                            |
+-------------------+       +----------+----------+
| Observation Layer +<------+ Kernel Telemetry    |
| ObservationRecord |       | aya-rs/eBPF         |
+---------+---------+       +---------------------+
          |
          v
+-------------------+       +---------------------+
| Risk Engine       +------->+ Policy Engine      |
| RiskAssessment    |        | Z3/policy config   |
+---------+---------+        +----------+----------+
          |                             |
          v                             v
+-------------------+       +---------------------+
| TrustState        |       | PolicyDecision      |
| AgentLineage      |       | allow/deny          |
+-------------------+       +---------------------+
```

## Unified Trust Model

Trust must be derived from observed behavior, not from the agent's declaration. The patched runtime computes:

```text
observed_risk = peer identity + process identity + namespace + uid factors
semantic_risk = RootAI or local semantic classification score
topology_risk = requested capability and path constraint score
declared_risk = optional client risk, allowed only to raise risk

weighted = semantic_risk * 0.55
         + observed_risk * 0.30
         + topology_risk * 0.15

fused_risk = max(weighted, semantic_risk, observed_risk, declared_risk_if_higher)
trust_score = 100 - fused_risk
```

Policy evaluation:

```text
deny if fused_risk > upper_safety_boundary
deny if trust_score < minimum_trust_score
deny if sequence_counter is replayed
deny if daemon-assessed risk jumps by more than lineage drift tolerance
otherwise prove fused_risk <= policy ceiling through Z3
```

Client-declared risk is now non-authoritative. A malicious client can over-report and self-restrict, but under-reporting cannot lower daemon-derived risk.

## Core Abstractions

| Abstraction | Ownership | Purpose | Security role |
| --- | --- | --- | --- |
| `ObservationRecord` | Observation Layer | Captures pid, uid, gid, executable, command line, namespace, timestamp | Binds request to observed local process identity |
| `SemanticIntent` | Semantic Analysis Layer | Classifies prompt, plan, source, and capability language | Detects intent not visible in scalar risk |
| `CapabilityProfile` | Risk Engine | Normalizes observed and requested capabilities | Bridges kernel facts with requested action surface |
| `RiskAssessment` | Risk Engine | Fuses observation, semantic, topology, and declared risk | Produces single risk/trust score |
| `PolicyDecision` | Policy Engine | Encodes allow/deny, reason, risk, trust | Creates auditable decision surface |
| `AgentLineage` | TrustState | Tracks pid sequence, first/last seen, max assessed risk | Blocks replay and assessed behavioral drift |
| `TrustState` | Agent Governance Runtime | Future aggregate trust state across agents | Basis for multi-agent lineage and delegation |

## Threat Model

| Threat | Current exposure | Mitigation | Complexity | Security impact | Performance impact |
| --- | --- | --- | --- | --- | --- |
| Client under-reports risk | Previously high | Patched: declared risk cannot lower fused risk | Done | High | Low |
| Replay of signed payload | Partially mitigated by sequence per pid | Keep lineage and add durable nonce/lease table | S | High | Low |
| PID reuse | Possible after process exit | Add start time from `/proc/{pid}/stat` and eBPF exec identity | M | High | Low |
| HMAC secret theft | Possible from environment | Move to kernel keyring or root-owned config with restricted permissions | M | High | Low |
| Partial socket reads | Possible for larger semantic payloads | Add framed protocol with max length and read loop | S | Medium | Low |
| Semantic evasion | High until RootAI service is integrated | Use parser registry, taint analysis, source inspection, and model-independent heuristics | H | High | Medium |
| Kernel telemetry blind spot | High | aya-rs tracepoints for execve/openat/connect/capability transitions | H | Very high | Medium |
| Policy bypass through direct execution | High if agent does not use broker | Execution Broker must mediate tool execution, not advisory only | H | Very high | Medium |
| Stale policy after reload failure | Medium | Validate policy before swap and expose health status | S | Medium | Low |
| Untrusted generated code artifacts | Medium | Quarantine examples and generated outputs | S | Medium | None |
| Browser script direct launch | High if used as security boundary | Replace with brokered action request | M | High | Low |

## RootAI Semantic Service Integration

Recommended local service contract:

```json
{
  "request_id": "uuid",
  "agent_id": "string",
  "prompt": "string",
  "plan": "string",
  "source_code": "string",
  "requested_capabilities": ["filesystem.write", "network.connect"],
  "observation": {
    "pid": 123,
    "uid": 1000,
    "exe": "/path/to/agent"
  }
}
```

Response:

```json
{
  "intent_class": "ProcessExecution",
  "confidence": 0.91,
  "risk_score": 82.0,
  "signals": ["subprocess", "network_connect", "tainted_path"],
  "symbols": ["open", "subprocess.run"],
  "taint_flows": ["prompt.url -> requests.get"],
  "policy_hints": ["requires_network_connect", "requires_filesystem_read"]
}
```

Service requirements:

1. Inspect prompts, plans, and source code independently.
2. Run parser registry selection by content type.
3. Extract symbols and imports.
4. Run taint analysis for prompt-to-tool and prompt-to-network flow.
5. Return intent and risk classifications with confidence and evidence.
6. Fail closed or degrade to local heuristic with a clear `semantic_service_unavailable` reason.

## eBPF / aya-rs Production Roadmap

| Step | Why | Complexity | Security impact | Performance impact |
| --- | --- | --- | --- | --- |
| Create `jinnguard-ebpf` crate with aya-bpf programs | Separates kernel probes from daemon | H | High | Low per event |
| Create userspace telemetry loader in `ts_cli` or `jinnguard_telemetry` | Loads, pins, and supervises probes | H | High | Medium startup cost |
| Add `execve` tracepoint | Establish immutable process lineage and argv hash | M | Very high | Low |
| Add `openat` tracepoint | Observe filesystem reads/writes before policy fusion | M | High | Medium on file-heavy agents |
| Add `connect` tracepoint | Observe outbound network intent | M | High | Low to medium |
| Add capability transition probe | Detect privilege changes and ambient capability drift | H | Very high | Low |
| Normalize events into `ObservationRecord` deltas | Keeps risk engine independent of kernel backend | M | High | Low |
| Add bounded ring buffer and drop counters | Prevents telemetry backpressure from blocking daemon | M | Medium | Low |
| Add kernel feature detection | Tracepoints vary by kernel | M | Medium | Low |

Capability transitions may require a tracepoint where available and a carefully reviewed kprobe/LSM fallback where the kernel does not expose the required tracepoint. The runtime should mark telemetry coverage in `TrustState`; missing coverage lowers trust.

## Refactor Plan

Phase 1, immediate code changes:

| Item | Status | Why | Complexity | Security impact | Performance impact |
| --- | --- | --- | --- | --- | --- |
| Add governance abstractions | Done | Establish stable trust model surface | M | High | Low |
| Make client risk upward-only | Done | Removes client-declared risk authority | S | High | Low |
| Fix Python signed envelope SDK | Done | Enables real IPC tests and demos | S | Medium | Low |
| Replace fake eBPF monitor with no-op plus roadmap interface | Done | Prevents false security claims | S | Medium | None |
| Add policy trust floor | Done | Gives policy engine trust dimension, not just risk ceiling | S | Medium | Low |
| Add framed IPC protocol | Pending | Prevent partial read and large semantic payload truncation | S | Medium | Low |
| Add socket permission hardening | Pending | Prevent unauthorized local clients from attempting requests | S | High | Low |

Phase 2, telemetry integration:

| Item | Why | Complexity | Security impact | Performance impact |
| --- | --- | --- | --- | --- |
| Implement aya-rs loader | Required for kernel telemetry | H | High | Medium startup |
| Add execve/openat/connect probes | Observed behavior becomes primary trust source | H | Very high | Medium |
| Add capability transition detection | Catches privilege drift | H | Very high | Low |
| Add telemetry coverage score | Missing probes reduce trust | M | High | Low |

Phase 3, semantic-policy fusion:

| Item | Why | Complexity | Security impact | Performance impact |
| --- | --- | --- | --- | --- |
| Run RootAI service over local UDS/gRPC | Makes semantic analysis independent and reusable | M | High | Medium |
| Feed parser symbols and taint results into `SemanticIntent` | Improves evidence quality | H | High | Medium |
| Convert policy YAML to typed policy constraints | Removes dead policy config | M | High | Low |
| Extend Z3 obligations beyond scalar ceiling | Proves capability, topology, and lineage constraints | H | High | Medium |

Phase 4, multi-agent governance:

| Item | Why | Complexity | Security impact | Performance impact |
| --- | --- | --- | --- | --- |
| Add stable `agent_id` and signed delegation tokens | PID alone cannot represent multi-agent identity | M | High | Low |
| Persist `AgentLineage` across daemon restarts | Prevents lineage reset attacks | M | High | Low |
| Model handoff graph and cumulative trust decay | Multi-agent systems need delegation-aware risk | H | High | Low |
| Require broker mediation for tool execution | Advisory checks are not enough | H | Very high | Medium |

Phase 5, production hardening:

| Item | Why | Complexity | Security impact | Performance impact |
| --- | --- | --- | --- | --- |
| Add audit log with tamper-evident hashes | Incident review and compliance | M | High | Low |
| Add metrics and health endpoint on control socket | Observability without weakening execution socket | M | Medium | Low |
| Add fuzzing for IPC and parser inputs | Malformed inputs are high probability | M | High | Medium in CI only |
| Add benchmarks for p50/p95 latency and memory | Validate README claims | M | Medium | CI/runtime only |
| Remove generated artifacts from git | Reduces operational ambiguity | S | Medium | None |

## Prioritized Backlog

1. Implement framed IPC with max payload length and explicit schema version.
2. Add process start time to `ObservationRecord` to mitigate PID reuse.
3. Add socket ownership and permission hardening for `/tmp/jinnguard.sock`.
4. Promote `governance.rs` into a shared crate with integration tests.
5. Convert `policy.yaml` into the canonical typed policy file or delete it.
6. Add RootAI service adapter and fail-closed semantic service mode.
7. Implement aya-rs execve tracepoint and event normalizer.
8. Implement openat/connect/capability telemetry and telemetry coverage scoring.
9. Replace thread-per-connection with bounded worker pool or async runtime.
10. Add audit ledger for `ObservationRecord`, `SemanticIntent`, `RiskAssessment`, and `PolicyDecision`.
11. Quarantine `run_three_body.sh`, generated outputs, release zip, `target/`, and `venv/`.
12. Add integration tests for allow, replay deny, tampered token deny, drift deny, semantic high-risk deny.

## Code Patches In This Pass

1. Added `ts_cli/src/governance.rs` with the requested core abstractions and trust fusion logic.
2. Rewired `ts_cli/src/main.rs` to use observation-derived risk, semantic classification, capability profiles, policy decisions, and assessed lineage drift.
3. Changed `ts_checker::PolicyEngine::execute_totality_audit` to verify daemon-assessed risk directly against the policy ceiling.
4. Replaced the fake eBPF monitor with an explicit no-op telemetry source and aya-rs probe roadmap types.
5. Added `minimum_trust_score` to `jinnguard_policy.json`.
6. Fixed the Python SDK to send the signed envelope expected by the daemon and restored the `Guard` demo wrapper.

## Operational Conclusion

Build toward an execution broker, not a policy-advice daemon. The decisive path is:

```text
observed kernel behavior + RootAI semantic evidence + topology constraints + policy proof
  -> fused trust state
  -> brokered execution allow/deny
```

Anything that does not feed this path should be treated as an example, fixture, or cleanup candidate until it is wired into the governance runtime.
