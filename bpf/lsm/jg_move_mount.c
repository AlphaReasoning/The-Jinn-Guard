// SPDX-License-Identifier: GPL-2.0
//
// bpf/lsm/jg_move_mount.c — Jinn Guard LSM hook for move_mount(2) (JG #50).
//
// Denies relocating mounts for tasks in the governed cgroup subtree, closing the
// move_mount(2) path (detached/anonymous mounts via fsmount + move_mount) that
// can otherwise assemble a nested mount tree without a classic mount(2) call.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "jg_common.h"
#include "../common/governed_floor.h"

SEC("lsm/move_mount")
int BPF_PROG(jg_move_mount, const struct path *from_path,
             const struct path *to_path)
{
    return jg_governed_floor_deny();
}

char LICENSE_move_mount[] SEC("license") = "GPL";
