# Self-hosted BPF-LSM CI runners

The `kernel-lsm-real` matrix job in [`.github/workflows/ci.yml`](../.github/workflows/ci.yml)
runs the **armed** kernel-LSM enforcement tests (default-deny egress #54, AF_UNIX
deputy denylist #55, and the rest of the `kernel_lsm` suite) against **real
kernels**. Those tests can only run where BPF-LSM is actually loadable, so they
execute on self-hosted runners rather than GitHub-hosted ones. The job is
`workflow_dispatch`-only, so normal push/PR CI is never queued against a
self-hosted runner that may be offline.

## Runners

| Runner | Distro / kernel | Labels |
|--------|-----------------|--------|
| `jinn1` | Debian 13 (trixie) / 6.12 | `self-hosted, bpf-lsm, jinn1` |
| `jinn2` | Ubuntu 24.04 / 6.17 | `self-hosted, bpf-lsm, jinn2` |
| `jinn3` | AlmaLinux 9.8 / 5.14 | `self-hosted, bpf-lsm, jinn3` |

The matrix keys off the per-host label, not the runner name, so each leg lands on
its intended kernel. 5.14 is the floor that exercises the oldest supported BPF
verifier. The runner **name** is independent of the label, so a host can be
renamed without touching the workflow.

## Per-runner requirements

- **Kernel with BPF-LSM active** — `bpf` must appear in
  `/sys/kernel/security/lsm`. If the kernel was built with `CONFIG_BPF_LSM=y` but
  `bpf` is not in the active stack, add it to the `lsm=` boot cmdline (preserving
  the existing LSMs) and reboot. Debian 13, Ubuntu 24.04, and AlmaLinux 9.8 all
  ship `bpf` active by default on their stock cloud kernels.
- **cgroup v2 unified** — `stat -fc %T /sys/fs/cgroup` returns `cgroup2fs`.
- **Build toolchain** — `clang`, `llvm`, libbpf + libelf dev headers, matching
  kernel headers, `make`, and a Rust toolchain (rustup) for the runner user.
- **Z3 development headers** — the enterprise daemon links Z3 (`z3-sys`). See the
  AlmaLinux gotcha below.
- **Passwordless sudo** for the runner user — the matrix steps run
  `sudo make -C bpf install` and execute the armed tests as root.
- Registered with labels `[self-hosted, bpf-lsm, <host>]` (`self-hosted` is added
  automatically by `config.sh`).

## Setup (two-phase)

The runner setup is delivered to each host out-of-band (these scripts contain no
secrets; the registration token is passed as a runtime argument, never embedded).

1. **Phase 1 — prepare the host.** Install the toolchain, create the dedicated
   `gha` runner user with passwordless sudo, install rustup for it, and ensure
   BPF-LSM is active (editing the `lsm=` cmdline + reboot only if `bpf` is not
   already in the active stack). Distro-aware: `apt` on Debian/Ubuntu, `dnf` on
   AlmaLinux.
2. **Phase 2 — register the runner.** Re-verify BPF-LSM + cgroup v2, download and
   checksum-verify the pinned runner release, then `config.sh --unattended` with
   the host's labels and a freshly minted registration token, and install it as a
   systemd service (`svc.sh install/start`).

Registration tokens are minted per host and expire ~1h, so mint them immediately
before running Phase 2.

## Distro gotchas

Two distro-specific quirks have to be handled or a fresh runner image will fail
the build step before any LSM test runs:

1. **Ubuntu `bpftool` is a virtual package with no install candidate.**
   `apt-get install bpftool` errors with *"Package 'bpftool' has no installation
   candidate"* (it is provided by `linux-tools-common` / a kernel-specific
   `linux-tools-*` package). The runner does **not** need `bpftool`, so this is
   harmless — install the rest of the toolchain without it.

2. **AlmaLinux installs the Z3 header one directory deeper.** The enterprise
   daemon links Z3 via `z3-sys`, whose build does `#include <z3.h>` and only
   searches `/usr/include`. On Debian/Ubuntu `libz3-dev` (pulled in via the `llvm`
   dependency) places the header at `/usr/include/z3.h`, so the build just works.
   On AlmaLinux, `z3-devel` installs it at **`/usr/include/z3/z3.h`** — inside a
   `z3/` subdirectory — so the build fails with:

   ```
   error: failed to run custom build command for `z3-sys v0.8.1`
     wrapper.h:1:10: fatal error: 'z3.h' file not found
   ```

   Fix: add the subdirectory to the C include path that `bindgen` (which `z3-sys`
   uses) honors. Append it to the runner's `.env` so it applies to every job, then
   restart the runner service:

   ```bash
   echo 'BINDGEN_EXTRA_CLANG_ARGS=-I/usr/include/z3' | sudo tee -a /opt/actions-runner/.env
   sudo systemctl restart actions.runner.<org>-<repo>.<runner-name>.service
   ```

## Dispatching the matrix

Once the runners are registered and idle, trigger the job against `main`:

```bash
gh workflow run ci.yml --ref main
# or, via the REST API:
# POST /repos/<org>/<repo>/actions/workflows/ci.yml/dispatches  {"ref":"main"}
```

A green run reports all three real-kernel legs (`Real-kernel LSM (<distro> k<ver>)`)
passing, which means the armed enforcement floors hold on 6.12, 6.17, and 5.14.
