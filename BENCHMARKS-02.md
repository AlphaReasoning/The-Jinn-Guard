# Jinn Guard — Benchmark Run 02

**Test #:** 02 (second host / cross-machine) · **Run date:** 2026-06-13 · **Host:** Azure cloud VM
**See also:** [`BENCHMARKS-01.md`](BENCHMARKS-01.md) — baseline (development laptop).
**Build:** `cargo build --release` (default features), end-to-end against the live daemon over the Unix-domain socket.

> Purpose: portability / cross-machine validation. Same validated distribution
> (Debian 13, kernel 6.12) as Run 01, but a different CPU and a cloud
> environment. Every measurement drives the **full governance pipeline** — no
> stage stubbed.

---

## Environment

| | |
|---|---|
| Provider | Microsoft Azure |
| CPU | Intel Xeon E5-2673 v4 @ 2.30 GHz (**2 vCPU**) |
| Kernel | Linux 6.12.90+deb13.1-cloud-amd64 (Debian 13) |
| Toolchain | rustc (stable), release profile (`opt-level=3`) |
| Transport | Unix-domain socket |
| Harness | `ts_cli/benches/stress_bench.rs`, `ts_cli/tests/swarm_attack.rs` |

To reproduce (works on a clean checkout — the harness auto-detects the binary):

```bash
cargo build --release
cargo bench --bench stress_bench
cargo test  --release --test swarm_attack
```

---

## 1. Latency — single client, full pipeline

10,000 sequential proposals, sorted wall-clock latency per request:

| Percentile | Latency |
|---|---|
| **P50** | **707 µs** |
| P75 | 797 µs |
| P90 | 927 µs |
| **P95** | **1,065 µs** |
| **P99** | **2,296 µs** |
| P99.9 | 4,128 µs |
| Max | 6,315 µs |

Single-client throughput: **~1,323 decisions/sec**. Median stays sub-millisecond
on two older cores.

---

## 2. Throughput — concurrent multi-agent

Persistent connections, N agents each issuing M requests. **Zero errors at every level.**

| Agents | Requests each | Total RPS | P50 | P95 | Errors |
|---|---|---|---|---|---|
| 10 | 500 | 3,074 | 580 µs | 1,869 µs | 0 |
| 50 | 200 | 3,014 | 588 µs | 2,354 µs | 0 |
| 100 | 100 | 3,020 | 594 µs | 2,600 µs | 0 |
| 500 | 20 | 2,822 | 589 µs | 396,945 µs | 0 |

> At 500 simultaneous agents the **tail** P95 stretches to ~397 ms under
> connection contention on only 2 cores, but throughput holds near 2,800 RPS with
> **zero errors and zero fail-opens** (same effect as Run 01, amplified by fewer
> cores).

### Mixed allow/deny workload

5,000 requests, 70% allow / 30% deny:

| Metric | Value |
|---|---|
| ALLOW (correctly) | 3,500 |
| DENY (correctly) | 1,500 |
| Misclassifications | **0** |
| Throughput | 1,343 RPS |

### Saturation curve

| Threads | RPS | P99 |
|---|---|---|
| 2 | 1,407 | 3 ms |
| 4 | 1,472 | 7 ms |
| 8 | 1,513 | 9 ms |
| 16 | — | SATURATED (P99 > 10 ms) |

(2 vCPU saturates earlier than Run 01's 8-core machine, as expected.)

---

## 3. Adversarial suite — agent attack resistance

`cargo test --release --test swarm_attack` — **12/12 passed, 0 failed, 0 fail-open.**
Identical pass/deny behavior to Run 01.

---

## 4. Cross-machine comparison (vs Run 01)

The **correctness** properties are identical on both hosts; only absolute
performance scales with the hardware.

| Metric | Run 01 (Ryzen, 8 cores) | Run 02 (Xeon, 2 vCPU) |
|---|---|---|
| Median latency (P50) | 257 µs | 707 µs |
| P95 / P99 | 366 / 463 µs | 1,065 / 2,296 µs |
| Single-client throughput | ~3,640/s | ~1,323/s |
| Peak concurrent throughput | ~6,672/s | ~3,074/s |
| Errors (all levels) | 0 | 0 |
| Mixed-workload misclassifications | 0 | 0 |
| Adversarial suite | 12/12, 0 fail-open | 12/12, 0 fail-open |

---

## 5. Scope & honesty notes

- This run validates portability across **hardware** and into a **cloud**
  environment on the **same distribution** (Debian 13). It does **not** broaden
  distribution coverage — that remains an open item (a non-Debian host is the
  next test to add as Run 03).
- Numbers are from a single 2-vCPU VM; they will vary with VM size and load.
  Treat them as representative of a small cloud node, not a universal guarantee.
- This is a validated research prototype / controlled-pilot MVP, not
  independently audited. See [`THREAT_MODEL.md`](THREAT_MODEL.md) §7 and §8.
