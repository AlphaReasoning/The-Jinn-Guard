// SPDX-License-Identifier: GPL-2.0
//
// bpf/lsm/jg_sb_mount.c — Jinn Guard LSM hook for mount(2) (JG #50).
//
// Denies new mounts for tasks in the governed cgroup subtree. Combined with the
// pivot_root and move_mount hooks, this blocks the filesystem side of building a
// nested container/sandbox root that would otherwise live outside the host LSM
// scope — the in-kernel complement to #53's capability denial. exec of mount /
// container-runtime binaries is already denied by the bprm allowlist.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "jg_common.h"
#include "../common/governed_floor.h"

SEC("lsm/sb_mount")
int BPF_PROG(jg_sb_mount, const char *dev_name, const struct path *path,
             const char *type, unsigned long flags, void *data)
{
    return jg_governed_floor_deny();
}

char LICENSE_sb_mount[] SEC("license") = "GPL";
