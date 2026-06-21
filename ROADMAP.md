# Jinn Guard Enforce Engine Roadmap
## Phase 1: Core Performance Stabilization (Completed)
- [x] Zero-dependency string token manual slicing implementation.
- [x] Ephemeral lease registration matrices with volatile sequence counter limits.
- [x] High-concurrency async benchmark validation (7,000+ RPS achieved).
## Phase 2: Decoupled Operations Layer (In Progress)
- [ ] Establish Dual-Channel IPC over separate control sockets (`jinnguard_control.sock`)

## Phase 3: Governance Surface Extensions (Planned)
Surfaced by the teaching lab ([`lab/`](lab/README.md)), which models a four-verdict
system while the daemon today emits only `ALLOW`/`DENY`. Design intent is recorded
in [`docs/agent_governance_extensions.md`](docs/agent_governance_extensions.md).
These are **not implemented** — they are scoped future work.
- [ ] Canary / honeypot detection: a `canary_resources` policy set + a tripwire
      decision path (short-circuits before allow/deny) + a `jinnguard_canary_trips_total`
      metric and alert event.
- [ ] Human-in-the-loop review: a non-terminal `HOLD_PENDING_REVIEW` verdict
      delivered over the Phase 2 control channel, **fail-closed on timeout**, with
      the hold and its resolution chained into the audit log.
