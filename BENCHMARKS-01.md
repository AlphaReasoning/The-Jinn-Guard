# Jinn Guard — Benchmark Run 01

**Test #:** 01 (baseline) · **Run date:** 2026-06-12 · **Host:** development laptop (Ryzen 5 7520U)
**See also:** [`BENCHMARKS-02.md`](BENCHMARKS-02.md) — second host (Azure / Xeon).
**Build:** `cargo build --release` (default features), end-to-end against the live daemon over the Unix-domain socket.

> Every measurement below drives requests through the **full governance pipeline** —
> protocol header → HMAC-SHA256 verify → parse → replay → identity → intent →
> runtime policy → quota → adaptive risk floor → Z3 SMT ceiling → response →
> lineage → hash-chained audit. No stage is stubbed or bypassed.

---

## Environment

| | |
|---|---|
| CPU | AMD Ryzen 5 7520U (8 logical cores) |
| Memory | 5.9 GB |
| Kernel | Linux 6.12.90 (Debian 13) |
| Toolchain | rustc 1.95.0, release profile (`opt-level=3`) |
| Transport | Unix-domain socket, one connection per request (latency runs) |
| Harness | `ts_cli/benches/stress_bench.rs`, `ts_cli/tests/swarm_attack.rs` |

To reproduce:

```bash
cargo build --release
cargo bench --bench stress_bench          # latency + throughput
cargo test --release --test swarm_attack  # adversarial suite
```

> The adversarial harness auto-detects the daemon binary (it prefers the build
> profile the test was compiled with, then falls back to the other), so the
> command above works on a clean checkout with no extra setup. To pin a specific
> binary, set `JINNGUARD_TEST_BINARY=/path/to/ts_cli`.

---

## 1. Latency — single client, full pipeline

10,000 sequential proposals, sorted wall-clock latency per request:

| Percentile | Latency |
|---|---|
| **P50** | **257 µs** |
| P75 | 272 µs |
| P90 | 312 µs |
| **P95** | **366 µs** |
| **P99** | **463 µs** |
| P99.9 | 645 µs |
| Max | 1,921 µs (1.9 ms) |

**Sub-millisecond through P99.9.** Single-client throughput: **~3,640 decisions/sec**.

---

## 2. Throughput — concurrent multi-agent

Persistent connections, N agents each issuing M requests. **Zero errors at every level.**

| Agents | Requests each | Total RPS | P50 | P95 | Errors |
|---|---|---|---|---|---|
| 10 | 500 | 6,672 | 1,188 µs | 1,343 µs | 0 |
| 50 | 200 | 6,521 | 1,198 µs | 1,839 µs | 0 |
| 100 | 100 | 6,564 | 1,193 µs | 1,870 µs | 0 |
| 500 | 20 | 6,121 | 1,216 µs | 36,688 µs | 0 |

> At 500 simultaneous agents the **tail** P95 stretches to ~37 ms under connection
> contention, but throughput holds at ~6,100 RPS with **zero errors and zero
> fail-opens**.

### Mixed allow/deny workload

5,000 requests, 70% allow / 30% deny:

| Metric | Value |
|---|---|
| ALLOW (correctly) | 3,500 |
| DENY (correctly) | 1,500 |
| Misclassifications | **0** |
| Throughput | 3,779 RPS |

### Saturation curve

| Threads | RPS | P99 |
|---|---|---|
| 2 | 5,016 | 0 ms |
| 4 | 4,247 | 2 ms |
| 8 | 4,862 | 2 ms |
| 16 | 4,834 | 4 ms |
| 32 | 5,130 | 8 ms |
| 64 | — | SATURATED (P99 > 10 ms) |

Sustains ~5,000 RPS with P99 ≤ 8 ms up to 32 concurrent threads.

---

## 3. Adversarial suite — agent attack resistance

`cargo test --release --test swarm_attack` — **12/12 passed, 0 failed, 0 fail-open.**
Each attack is driven concurrently at the live daemon; the deny count is asserted
exactly in the test source.

| # | Attack | Volume | Result |
|---|---|---|---|
| 1 | **Replay storm** — re-send a captured signed packet | 50 | 1 allowed, **49 `DENY_REPLAY_ATTACK`** |
| 2 | **HMAC forgery flood** — tampered signatures | 100 | **100 `DENY_TAMPERED_TOKEN`** |
| 3 | **Intent injection** — disallowed intents (`rm_all`) | 200 | **200 `DENY_INTENT_NOT_ALLOWED`** |
| 4 | **Quota-exhaustion race** — concurrent over quota | many | **exactly 5 allowed**, rest denied |
| 5 | **Risk-ceiling coordinated breach** — risk 95 | 50 | **50 `DENY`** (Z3 ceiling holds) |
| 6 | **Anonymous-agent flood** — no agent id | 200 | **200 `DENY_ANONYMOUS_AGENT`** |
| 7 | **Unknown-agent-ID flood** — `ghost` | 100 | **100 `DENY_UNKNOWN_AGENT_ID`** |
| 8 | **Protocol-version flood** — bad version | 50 | **50 `DENY_BAD_VERSION`** |
| 9 | **Delegation-chain forgery** — forged delegation tokens | 20 | **20 denied** |
| 10 | **Path-traversal via MCP** | 20 | **20 denied** |
| 11 | **Concurrent mixed attack** — 8 vectors at once | 400 | **349 denied + 50 legit allowed**, no cross-contamination |
| 12 | **Daemon resilience after the storm** | — | stays healthy; legit ALLOW in < 50 ms |

**Summary:** >1,200 adversarial requests across 8 attack classes, fired
concurrently — **0 fail-open, 0 misclassification**, the daemon survives intact,
and a legitimate request mixed into the storm is still correctly allowed in
sub-millisecond time.

---

## 4. Scope & honesty notes

- Numbers are from a **single Debian / Linux 6.12 host** (the hardware above); they
  will vary with CPU, kernel, and load. Treat them as representative of this class
  of machine, not a universal guarantee.
- Latency/throughput here measure the **userspace governance decision path** over
  the UDS. Kernel-LSM enforcement (eBPF) was validated separately, armed, on real
  hardware (2,500 enforced operations, 0 fail-open) — see
  [`CHANGELOG.md`](CHANGELOG.md) and [`THREAT_MODEL.md`](THREAT_MODEL.md).
- This is a validated research prototype / controlled-pilot MVP, not independently
  audited. See [`THREAT_MODEL.md`](THREAT_MODEL.md) §7 and §9 for residual risks.
