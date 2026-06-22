// SPDX-License-Identifier: GPL-2.0
//
// bpf/lsm/jg_sb_pivotroot.c — Jinn Guard LSM hook for pivot_root(2) (JG #50).
//
// Denies pivot_root for tasks in the governed cgroup subtree, so a governed
// agent cannot switch into an alternate root it has staged (the second half of
// the classic container-construction path after mount).

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "jg_common.h"
#include "../common/governed_floor.h"

SEC("lsm/sb_pivotroot")
int BPF_PROG(jg_sb_pivotroot, const struct path *old_path,
             const struct path *new_path)
{
    return jg_governed_floor_deny();
}

char LICENSE_sb_pivotroot[] SEC("license") = "GPL";
