# Jinn Guard — Benchmark Run 03

**Test #:** 03 (distribution coverage) · **Run date:** 2026-06-14 · **Host:** Azure cloud VM (`jinn2`)
**See also:** [`BENCHMARKS-01.md`](BENCHMARKS-01.md) — baseline laptop · [`BENCHMARKS-02.md`](BENCHMARKS-02.md) — second host, same distro.
**Build:** `cargo build --release` (default features) + `--features kernel_telemetry` for the kernel tiers, end-to-end against the live daemon.

> Purpose: **broaden distribution + kernel coverage.** Runs 01 and 02 both used
> Debian 13 / kernel 6.12. This run is a **different distribution and a newer
> kernel generation** — Ubuntu 24.04 LTS on kernel 6.17 — and exercises the
> **real eBPF-LSM allow/deny enforcement path**, not just userspace logic. This
> is the "non-Debian host" that Run 02 §5 flagged as the next test to add.

---

## Environment

| | |
|---|---|
| Provider | Microsoft Azure |
| CPU | 2 vCPU |
| Memory | 7.7 GiB |
| Distribution | **Ubuntu 24.04.4 LTS** |
| Kernel | **Linux 6.17.0-1018-azure** |
| Active LSMs | `lockdown,capability,landlock,yama,apparmor,bpf,ima,evm` (bpf armed — see below) |
| BTF | present (`/sys/kernel/btf/vmlinux`) |
| cgroup | v2 (`cgroup2fs`) |
| Toolchain | rustc/cargo 1.96.0, release profile |
| Harness | `scripts/run_professor_validation.sh --arm` (Tiers 1, 3, 4) |

### Distribution-portability steps (Ubuntu-specific, Debian did not need these)

These are honest deltas from the Debian runs and are documented so the result is
reproducible:

1. **Arm BPF-LSM.** Ubuntu's default LSM list does **not** include `bpf`. Append
   it to the existing list via the kernel command line and reboot:
   ```bash
   # /etc/default/grub
   GRUB_CMDLINE_LINUX="lsm=lockdown,capability,landlock,yama,apparmor,ima,evm,bpf"
   sudo update-grub && sudo reboot
   # verify after reboot:
   grep bpf /sys/kernel/security/lsm
   ```
2. **bpftool** is not a standalone apt package on Ubuntu and the Azure
   `linux-tools` package omits the binary. Install `linux-tools-generic` and put
   its `bpftool` (v7.4.0; cross-kernel-version safe for `btf dump`) on `PATH`.
3. **Build dependency:** `libssl-dev` (+ `pkg-config`) is required by the
   `openssl-sys` transitive dependency. (Now reflected in the README prereqs.)

---

## 1. Full automated test suite (Tier 1)

`cargo build --release` succeeded, then the full suite:

| Group | Result |
|---|---|
| Z3 solver | 4 passed |
| Unit | 87 passed |
| Integration | 13 passed |
| Swarm-attack (adversarial) | **12 passed, 0 failed, 0 fail-open** |
| (ignored — env-gated) | 6 ignored |
| **Total** | **116 passed, 0 failed** |

Behavior is identical to the Debian runs — the userspace governance pipeline is
distribution-independent, as expected.

---

## 2. Kernel-LSM enforcement (Tier 4 — armed, cgroup-scoped) — the headline

The real test of this run: **load the eBPF-LSM objects (built against this
kernel's own BTF) and enforce allow/deny in-kernel on 6.17.** Enforcement is
cgroup-scoped to a dedicated test cgroup; the rest of the host is structurally
out of scope. Each surface ran 500 operations (250 expected-allow / 250
expected-deny); safe mode ran 250 (all expected-allow, audit-only).

| Surface | Ops | Correct allow | Correct deny | **fail-open** | incorrect | timeout | P50 | P95 | P99 | Max |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| execve            | 500 | 250 | 250 | **0** | 0 | 0 | 998 µs | 1,430 µs | 1,713 µs | 9,001 µs |
| filesystem create | 500 | 250 | 250 | **0** | 0 | 0 | 15 µs | 56 µs | 88 µs | 239 µs |
| filesystem unlink | 500 | 250 | 250 | **0** | 0 | 0 | 14 µs | 32 µs | 62 µs | 224 µs |
| TCP connect       | 500 | 250 | 250 | **0** | 0 | 0 | 53 µs | 99 µs | 148 µs | 434 µs |
| UDP sendto        | 500 | 250 | 250 | **0** | 0 | 0 | 4 µs | 9 µs | 21 µs | 50 µs |
| safe mode (audit) | 250 | 250 |   — | **0** | 0 | 0 | 61 µs | 1,236 µs | 2,108 µs | 2,280 µs |
| **Total** | **2,750** | **1,500** | **1,250** | **0** | **0** | **0** | | | | |

> **2,750 enforced operations on Ubuntu 24.04 / kernel 6.17: 0 fail-open, 0
> incorrect decisions, 0 timeouts.** The eBPF objects loaded and verified cleanly
> on a kernel two generations newer than the original validation host — CO-RE
> portability held. Safe mode correctly blocked nothing (audit-only invariant
> intact).

---

## 3. Kernel path resolution (Tier 3 — audit-only)

The LSM hooks loaded in safe mode and resolved **full absolute file paths**
(the CVE-2026-002 fix) on 6.17 — audit-only, nothing blocked. PASS.

---

## 4. Userspace latency & throughput (CPU-isolated)

The userspace `stress_bench` harness (same as Runs 01–02) was run on jinn2. Its
daemon fsyncs the hash-chained audit log + lineage (under `/tmp`) per decision,
and jinn2's managed OS disk is Standard-HDD class (`dd … oflag=dsync` = 663 kB/s,
~6 ms/sync-write, and `/tmp` is on that root disk). So the **on-disk** run is
storage-bound at ~54 RPS / 17 ms P50 — a property of this VM's disk, not the OS.
Mounting tmpfs over `/tmp` moves those fsyncs to RAM and isolates the CPU/OS path.
With that, jinn2 (Ubuntu 24.04 / 6.17) lands **essentially identical to jinn1**
(Debian 13 / 6.12) on the same Xeon E5-2673 v4 — confirming the governance
pipeline is distribution-independent.

### Single-client latency (10,000 sequential, full pipeline)

| Percentile | jinn1 (Debian, Run 02) | jinn2 (Ubuntu, tmpfs `/tmp`) |
|---|---|---|
| P50 | 707 µs | **717 µs** |
| P95 | 1,065 µs | **998 µs** |
| P99 | 2,296 µs | **1,422 µs** |
| Single-client RPS | ~1,323 | **~1,343** |

### Concurrent throughput (tmpfs `/tmp`; 0 errors at every level)

| Agents | Total RPS | P50 |
|---|---|---|
| 10 | 3,250 | 573 µs |
| 50 | 3,202 | 580 µs |
| 100 | 3,229 | 569 µs |
| 500 | 2,966 | 587 µs |

Mixed 70/30 allow/deny: **3,500 / 1,500 classified correctly, 0 misclassifications.**
Saturation: ~1,483–1,604 RPS across 2–8 threads, saturating at 16 (same shape as
Run 02).

> **Storage caveat / operational finding.** The on-HDD figure (~54 RPS) is real
> and worth heeding: the audit log's per-decision `fsync` makes throughput
> sensitive to **audit-log storage latency**. In production, put
> `/var/log/jinnguard` (and the lineage file) on fast local storage (SSD/NVMe).
> The tmpfs figures above isolate the CPU/OS path for the cross-distro comparison;
> they are **not** a claim that durable auditing is free.

---

## 5. Cross-distribution comparison

| Property | Run 01/02 (Debian 13 / 6.12) | Run 03 (Ubuntu 24.04 / 6.17) |
|---|---|---|
| Full automated suite | pass | **116 pass** |
| Adversarial suite | 12/12, 0 fail-open | **12/12, 0 fail-open** |
| Kernel LSM enforcement | 2,500 ops, 0 fail-open | **2,750 ops, 0 fail-open** |
| eBPF CO-RE load/verify | OK (6.12) | **OK (6.17)** |
| Single-client P50 (CPU-isolated) | 707 µs | **717 µs** |
| Peak concurrent RPS (CPU-isolated) | ~3,074 | **~3,250** |
| Distribution | Debian | **Ubuntu** |

Correctness properties and the userspace performance envelope are effectively
identical across both distributions and both kernel generations on equivalent
hardware + storage.

---

## 6. Scope & honesty notes

- **What this run adds:** a **second distribution** (Ubuntu) and a **newer kernel
  generation** (6.17), with real in-kernel enforcement validated on both. The
  "Debian-only" limitation noted in Run 02 §5 is now closed for two distros.
- **Userspace numbers are reported CPU-isolated (tmpfs `/tmp`); see §4.** The raw
  on-HDD run measured ~54 RPS / 17 ms P50 — that is this VM's Standard-HDD managed
  disk (`dd … oflag=dsync` = 663 kB/s, ~6 ms/sync-write), **not** an Ubuntu
  property; the CPU is the same Xeon E5-2673 v4 as jinn1 at **0% steal**. With the
  audit/lineage fsyncs on tmpfs, jinn2 matches jinn1 (P50 717 vs 707 µs). The
  kernel-enforcement results in §2 are storage-independent (create/unlink at
  14–15 µs P50, not disk-bound).
- Numbers are from a single 2-vCPU VM; treat them as representative of a small
  cloud node, not a universal guarantee. The kernel-enforcement latencies are
  end-to-end per governed operation including the round trip to the daemon.
- Still a validated research prototype / controlled-pilot MVP, not independently
  audited. See [`THREAT_MODEL.md`](THREAT_MODEL.md).
- **Next coverage target:** a RHEL-family host (Fedora / Rocky / AlmaLinux) would
  be Run 04 and broaden the matrix beyond the Debian/Ubuntu (dpkg) family.
