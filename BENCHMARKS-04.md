# Jinn Guard — Benchmark Run 04

**Test #:** 04 (RHEL-family / third distribution) · **Run date:** 2026-06-15 · **Host:** Azure cloud VM (`jinn3`)
**See also:** [`BENCHMARKS-01.md`](BENCHMARKS-01.md) · [`BENCHMARKS-02.md`](BENCHMARKS-02.md) · [`BENCHMARKS-03.md`](BENCHMARKS-03.md)
**Build:** `cargo build --release` + `--features kernel_telemetry` for the kernel tiers, end-to-end against the live daemon.

> Purpose: extend coverage into the **RHEL family** (a third, distinct kernel
> lineage) under **SELinux Enforcing**, and validate real eBPF-LSM allow/deny
> enforcement there. This run also **found and fixed a real fail-open bug**
> (CVE-2026-003) — see §6 — which is itself the strongest argument that a
> distro-matrix is worth running.

---

## Environment

| | |
|---|---|
| Provider | Microsoft Azure |
| CPU | Intel Xeon Platinum 8272CL @ 2.60 GHz (Cascade Lake), **2 vCPU** |
| Distribution | **AlmaLinux 9.8 (Olive Jaguar)** — RHEL 9 rebuild |
| Kernel | **Linux 5.14.0-687.5.3.el9_8** (RHEL backport — a third kernel lineage vs Debian 6.12 / Ubuntu 6.17) |
| LSM | `lockdown,capability,landlock,yama,selinux,bpf` — **SELinux Enforcing**, `bpf` **pre-armed** (no GRUB change needed) |
| BTF | present |
| cgroup | v2 |
| Toolchain | rustc/cargo 1.96.0, release profile |
| Harness | `scripts/run_professor_validation.sh --arm` (Tiers 1, 3, 4) |

### RHEL-family build deltas (Debian/Ubuntu did not need these)

Honest, reproducible portability notes:

1. **`bpf` is already in the LSM list** alongside SELinux — unlike Ubuntu, no
   `lsm=` GRUB edit/reboot is required.
2. **`bpftool`** is a first-class `dnf` package (no `linux-tools` workaround).
3. **`libbpf-devel`** lives in the **CRB** repo (disabled by default):
   `sudo dnf config-manager --set-enabled crb`.
4. **Z3** comes from **EPEL** (`z3-devel`); its header is under `/usr/include/z3/`,
   which `z3-sys` doesn't find by default — set
   `Z3_SYS_Z3_HEADER=/usr/include/z3/z3.h` and
   `BINDGEN_EXTRA_CLANG_ARGS=-I/usr/include/z3`.
5. **`openssl-devel`** is required (the `openssl-sys` dependency).

---

## 1. Full automated test suite (Tier 1)

`cargo build --release` succeeded; full suite **116 passed, 0 failed**
(4 Z3 + 87 unit + 13 integration + **12 swarm-attack**, 6 env-gated ignored).
Behavior identical to the Debian/Ubuntu runs — the userspace pipeline is
distribution-independent.

---

## 2. Kernel-LSM enforcement (Tier 4 — armed, cgroup-scoped, SELinux Enforcing)

eBPF objects built against this kernel's 5.14 BTF, loaded and attached **with no
SELinux denial**, enforcing allow/deny in-kernel. Each surface: 500 operations
(250 expected-allow / 250 expected-deny); safe mode 250 (audit-only).

| Surface | Ops | Correct allow | Correct deny | **fail-open** | incorrect | P50 | P95 | P99 | Max |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| execve            | 500 | 250 | 250 | **0** | 0 | 668 µs | 872 µs | 957 µs | 1,182 µs |
| filesystem create | 500 | 250 | 250 | **0** | 0 | 14 µs | 38 µs | 67 µs | 139 µs |
| filesystem unlink | 500 | 250 | 250 | **0** | 0 | 7 µs | 17 µs | 212 µs | 363 µs |
| TCP connect       | 500 | 250 | 250 | **0** | 0 | 24 µs | 47 µs | 166 µs | 304 µs |
| UDP sendto        | 500 | 250 | 250 | **0** | 0 | 2 µs | 3 µs | 4 µs | 42 µs |
| safe mode (audit) | 250 | 250 |   — | **0** | 0 | 44 µs | 750 µs | 1,340 µs | 1,640 µs |
| **Total** | **2,750** | **1,500** | **1,250** | **0** | **0** | | | | |

> **2,750 enforced operations on AlmaLinux 9 / kernel 5.14 under SELinux
> Enforcing: 0 fail-open, 0 incorrect decisions, 0 timeouts** — *after* the
> CVE-2026-003 fix (§6). The eBPF programs verified and loaded cleanly on a third
> kernel lineage; SELinux and the BPF-LSM coexisted without interference.

---

## 3. Kernel path resolution (Tier 3 — audit-only)

LSM hooks loaded in safe mode and resolved full absolute file paths
(CVE-2026-002 fix) on 5.14 — audit-only, nothing blocked. PASS.

---

## 4. Cross-distribution comparison

| Property | Debian 13 / 6.12 | Ubuntu 24.04 / 6.17 | AlmaLinux 9 / 5.14 |
|---|---|---|---|
| Full automated suite | pass | 116 pass | **116 pass** |
| Adversarial suite | 12/12, 0 fail-open | 12/12, 0 fail-open | **12/12, 0 fail-open** |
| Kernel LSM enforcement | 2,500 ops, 0 fail-open | 2,750 ops, 0 fail-open | **2,750 ops, 0 fail-open** |
| eBPF CO-RE load/verify | OK (6.12) | OK (6.17) | **OK (5.14)** |
| Default LSM | (AppArmor/none) | AppArmor → arm bpf | **SELinux Enforcing** (bpf pre-armed) |
| Package family | dpkg | dpkg | **rpm/dnf (CRB+EPEL)** |

Enforcement correctness now holds across **three distributions and three kernel
generations**, including a RHEL-family host under SELinux Enforcing.

---

## 5. Userspace latency & throughput (CPU-isolated, tmpfs `/tmp`)

`stress_bench` was run with the daemon's fsync'd audit log + lineage on tmpfs
(as in [`BENCHMARKS-03.md`](BENCHMARKS-03.md) §4, to isolate the CPU/OS path from
this VM's managed-disk write latency).

> **Hardware note.** jinn3 runs an **Intel Xeon Platinum 8272CL @ 2.6 GHz
> (Cascade Lake)** — a newer microarchitecture and higher clock than Runs 01–02's
> Xeon E5-2673 v4 @ 2.3 GHz (Broadwell). So jinn3's **absolute** latencies are
> lower: a CPU difference, not a distro one. What's comparable across distros is
> **correctness** (identical) and the **shape** of the curves.

### Single-client latency (10,000 sequential, full pipeline)

| Percentile | jinn3 (AlmaLinux 9, tmpfs) |
|---|---|
| P50 | 475 µs |
| P95 | 511 µs |
| P99 | 531 µs |
| Single-client RPS | ~2,075 |

### Concurrent throughput (tmpfs `/tmp`; 0 errors at every level)

| Agents | Total RPS | P50 |
|---|---|---|
| 10 | 6,061 | 315 µs |
| 50 | 6,054 | 311 µs |
| 100 | 6,039 | 310 µs |
| 500 | 5,516 | 311 µs |

Mixed 70/30 allow/deny: **3,500 / 1,500 classified correctly, 0 misclassifications**
(2,274 RPS). Saturation: ~2,572–2,670 RPS across 2–16 threads, saturating at 32.

### Cross-distribution performance (effectively CPU-bound)

Userspace numbers across all three validation hosts. jinn1 used fast local
storage; jinn2/jinn3 placed the audit log + lineage on tmpfs `/tmp` — so all
three are effectively CPU-bound, isolating the OS/pipeline from disk latency.

| Host · distro / kernel | CPU (2 vCPU) | P50 | P95 | Single RPS | Peak concurrent RPS |
|---|---|---:|---:|---:|---:|
| jinn1 · Debian 13 / 6.12 (Run 02) | Xeon E5-2673 v4 @ 2.3 GHz | 707 µs | 1,065 µs | ~1,323 | ~3,074 |
| jinn2 · Ubuntu 24.04 / 6.17 (Run 03) | Xeon E5-2673 v4 @ 2.3 GHz | 717 µs | 998 µs | ~1,343 | ~3,250 |
| jinn3 · AlmaLinux 9 / 5.14 (Run 04) | Xeon Platinum 8272CL @ 2.6 GHz | **475 µs** | **511 µs** | **~2,075** | **~6,061** |

Two reads, deliberately kept separate:

- **Distribution independence (controlled — identical CPU).** jinn1 (Debian) and
  jinn2 (Ubuntu) run the *same* Xeon E5-2673 v4: P50 **707 vs 717 µs** (~1.4%),
  single-client **~1,323 vs ~1,343 RPS**, peak concurrent **~3,074 vs ~3,250 RPS**.
  Within run-to-run noise → the governance pipeline performs the **same across
  distributions**. This is the defensible cross-distro performance claim.
- **CPU scaling (not a distro effect).** jinn3 (AlmaLinux) shows ~1.5× lower P50
  and ~1.9× higher peak throughput — but on a newer **Xeon Platinum 8272CL
  (Cascade Lake @ 2.6 GHz)**. That reflects the **hardware**, not the distribution;
  it should **not** be read as "RHEL/AlmaLinux is faster." It does show the
  pipeline scales cleanly with newer silicon.

> Same storage caveat as Run 03: the **on-disk** figure would be audit-fsync-bound
> (tens of RPS on this VM's managed disk) — put `/var/log/jinnguard` and the
> lineage file on fast local storage (SSD/NVMe) in production.

---

## 6. Scope & honesty notes

- Absolute latencies above reflect jinn3's (faster) CPU; treat them as
  representative of a small modern cloud node, not a universal guarantee. Kernel-
  enforcement latencies (§2) are end-to-end per governed operation.
- Single 2-vCPU VM; treat absolute latencies as representative of a small cloud
  node, not a universal guarantee. Kernel-enforcement latencies are end-to-end
  per governed operation.
- Still a validated research prototype / controlled-pilot MVP, not independently
  audited. See [`THREAT_MODEL.md`](THREAT_MODEL.md).

---

## 7. What this run found and fixed — CVE-2026-003

On the **first** armed run, AlmaLinux 9 / 5.14 exposed a **fail-open** in
`socket_connect`: a *variable* fraction (~30–55% under load) of denied TCP
connects were wrongly allowed, while UDP/exec/file held at 0. Investigation
(documented in full in `THREAT_MODEL.md`):

1. **`setenforce 0` ruled out SELinux** — it failed identically permissive.
2. A **minimal standalone reproducer** (`bpf/probe/connect_min/`, branch
   `probe/lsm-connect-min`) showed the **kernel honors a sleepable
   `socket_connect -EPERM` deterministically** — so the bug was Jinn Guard's,
   **not AlmaLinux or the kernel**.
3. Incrementally extending the reproducer isolated **two independent causes**:
   - **Load-window** — hooks were attached before the deny maps were populated
     (empty-policy allow window). Fixed by **populate-then-attach**.
   - **`sock->type` width bug** — the hook read the kernel's 2-byte `short
     sock->type` into a 4-byte `int`, pulling adjacent padding that intermittently
     tripped a fail-open type gate. Fixed by reading the correct width. (This bug
     was **latent on every distro** — Debian/Ubuntu merely got zero padding.)

Both fixes landed (CVE-2026-003) and this run is the **post-fix re-validation**:
`fail_open=0` on every surface. The distro-matrix did exactly its job.
