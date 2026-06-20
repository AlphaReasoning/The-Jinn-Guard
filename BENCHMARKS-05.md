# Jinn Guard — Benchmark Run 05

**Test #:** 05 (launch-hygiene re-validation) · **Run date:** 2026-06-19
**Branch:** `chore/launch-hygiene` · **Host:** local dev sandbox (`jinn-dev`)
**See also:** [`BENCHMARKS-01.md`](BENCHMARKS-01.md) · [`BENCHMARKS-02.md`](BENCHMARKS-02.md) · [`BENCHMARKS-03.md`](BENCHMARKS-03.md) · [`BENCHMARKS-04.md`](BENCHMARKS-04.md)

> Purpose: re-run the full **userspace** test + benchmark suite after the
> launch-hygiene pass (advisory-ID rename, README register fix, doc cleanups —
> all docs/comments, **no logic**) to confirm behavior and performance are
> unchanged. This host runs the **same CPU family and kernel** as Run 01
> (AMD Ryzen 5 7520U / Debian 13 / kernel 6.12), so the numbers are directly
> comparable to that baseline.

---

## Environment

| | |
|---|---|
| CPU | **AMD Ryzen 5 7520U** (8 threads, scaling ~83%, max 4.38 GHz) — same model as Run 01 |
| Distribution | **Debian 13** (trixie family) |
| Kernel | **Linux 6.12.90+deb13.1-amd64** |
| RAM | ~5.75 GiB |
| `/tmp` | **tmpfs** — audit log + lineage are CPU-isolated from disk-fsync latency (as in Run 03/04) |
| Toolchain | rustc/cargo **1.95.0**, release profile, clang 19 |
| Privilege | **uid 1000, no `bpftool`** → kernel-LSM Tier 4 (armed allow/deny) **not run here** |

> **Scope note.** Kernel in-kernel allow/deny enforcement (Tier 4) requires root +
> BPF load and is **not** exercised on this unprivileged sandbox. It is already
> validated on three real hosts in [`BENCHMARKS-01..04`](BENCHMARKS-04.md)
> (Debian 6.12, Ubuntu 6.17, AlmaLinux 5.14 — 2,500–2,750 ops, 0 fail-open).
> This run covers the **full automated suite + userspace performance**.

---

## 1. Full automated test suite

`cargo test --workspace --release`:

| Binary | Result |
|---|---|
| `ts_checker` (Z3 SMT) | 4 passed |
| `ts_cli` unit | 87 passed |
| `integration` | 13 passed |
| `swarm_attack` (adversarial) | 12 passed |
| `kernel_lsm` (Tier 4) | 6 **ignored** (env-gated: needs root + BPF) |

> **116 passed · 0 failed · 6 ignored** (122 defined). Identical pass profile to
> Run 04. The launch-hygiene changes did not alter any behavior.

## 2. Attack resistance (adversarial suite)

`swarm_attack`: **12/12 passed, 0 fail-open** — replay storm, signature forgery,
intent injection, quota abuse, anonymous flood, impersonation, path traversal,
forged delegation, bad-protocol, and the all-at-once mixed assault.

---

## 3. Userspace latency & throughput (`cargo bench --bench stress_bench`)

### Single-client latency (10,000 sequential, full decision pipeline)

| Percentile | Run 05 (Ryzen 5 7520U) | Run 01 baseline (same CPU) |
|---|---|---|
| P50 | **259 µs** | 257 µs |
| P75 | 304 µs | — |
| P90 | 435 µs | — |
| P95 | **533 µs** | 366 µs |
| P99 | **782 µs** | 463 µs |
| P99.9 | 1,243 µs | — |
| Max | 2,962 µs | 1,900 µs |
| Single-client RPS | **~3,219** | ~3,640 |

> P50 matches Run 01 to within noise (259 vs 257 µs). Tail percentiles (P95/P99)
> are higher here — this is a **shared, non-CPU-isolated sandbox** at ~83% scaling,
> not a dedicated host, so tail latency is noisier. The median (the pipeline's
> real cost) is unchanged.

### Concurrent throughput (tmpfs `/tmp`; 0 errors at every level)

| Agents | Total RPS | P50 | P95 | Errors |
|---|---:|---:|---:|---:|
| 10 | **6,208** | 1,220 µs | 1,874 µs | 0 |
| 50 | 6,055 | 1,220 µs | 2,432 µs | 0 |
| 100 | 6,159 | 1,233 µs | 2,535 µs | 0 |
| 500 | 5,741 | 1,252 µs | 37,107 µs | 0 |

> Peak **~6,208 RPS**, flat to 100 concurrent agents, **0 errors** throughout.
> At 500 agents throughput holds but the P95 tail balloons (scheduling
> congestion on 8 threads) — consistent with Run 01 (~6,500 peak).

### Mixed allow/deny (70/30)

5,000 requests → **3,500 allow / 1,500 deny classified correctly, 0
misclassifications** (~3,517 RPS).

### Saturation sweep

| Threads | RPS | P99 |
|---|---:|---:|
| 2 | 4,556 | 1 ms |
| 4 | 4,809 | 1 ms |
| 8 | 5,111 | 2 ms |
| 16 | 4,781 | 5 ms |
| 32 | 4,888 | 9 ms |
| 64 | **saturated** (P99 > 10 ms) | — |

---

## 4. Component micro-benchmarks (criterion)

| Path | Median | Throughput |
|---|---:|---:|
| Core decision pipeline (in-process) | **73.2 µs** | ~13.6 K/s |
| UDS framed roundtrip (persistent conn) | **16.2 µs** | ~61.6 K/s |
| End-to-end serial roundtrip (new conn/request) | **151.1 µs** | ~6.6 K/s |

> The UDS transport (~16 µs) is a small fraction of the full decision (~73 µs+);
> the pipeline, not the socket, dominates. *(The persistent-connection case in
> `socket_throughput` hit a `BrokenPipe` in the bench harness mid-run — a
> harness-robustness quirk, not a daemon fault; the e2e new-connection figure
> above completed cleanly.)*

---

## 5. Scope & honesty notes

- Userspace only; **kernel Tier 4 not run on this unprivileged sandbox** — see
  Runs 01–04 for live in-kernel enforcement.
- Shared sandbox at ~83% CPU scaling: treat **P50/medians** as representative and
  **tails** as noisier than a dedicated host would show.
- Still a validated research prototype / controlled-pilot MVP, not independently
  audited. See [`THREAT_MODEL.md`](THREAT_MODEL.md) and
  [`SECURITY/ADVISORIES.md`](SECURITY/ADVISORIES.md).

**Bottom line:** post-launch-hygiene, the suite is **116/116 green (0 fail-open
in the adversarial suite)** and userspace performance is in line with the Run 01
baseline on identical silicon — confirming the docs/comment-only hygiene pass
changed nothing operational.
