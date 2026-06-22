// SPDX-License-Identifier: GPL-2.0
//
// bpf/lsm/jg_file_open.c — Jinn Guard LSM hook for file_open(2) (JG #51).
//
// Denies a governed task from opening the hardware-virtualization device
// /dev/kvm, neutering KVM-accelerated VM and microVM launch (QEMU/KVM,
// Firecracker, Cloud Hypervisor, crosvm, ...). A nested VM is the strongest
// escape from the host LSM scope — the guest kernel runs entirely outside our
// hooks — so this closes the hardware-acceleration door at the kernel floor,
// the device-node complement to #50's mount nesting and #53's capability denial.
//
// /dev/kvm is a misc character device with a FIXED minor (KVM_MINOR = 232,
// MISC_MAJOR = 10), part of the kernel UAPI, so we match it by the inode's
// i_rdev with no path walk. file_open is a hot, system-wide hook: the rdev
// match runs FIRST and bails for every non-KVM open (the overwhelming common
// case) before the more expensive governed-scope check ever runs.
//
// Residual (documented in THREAT_MODEL.md, nested-governance boundary): pure
// software emulation (TCG/qemu without /dev/kvm) needs no device node, but it
// still requires exec of the emulator binary, already denied by the bprm
// allowlist; and it offers no fast nested kernel, only a slow interpreter the
// host hooks still observe.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "jg_common.h"
#include "../common/governed_floor.h"

// Kernel dev_t encoding (include/linux/kdev_t.h): major in the high bits, minor
// in the low MINORBITS (20) bits.
#define JG_MINORBITS 20
#define JG_MINORMASK ((1U << JG_MINORBITS) - 1)
#define JG_MAJOR(dev) ((unsigned int)((dev) >> JG_MINORBITS))
#define JG_MINOR(dev) ((unsigned int)((dev) & JG_MINORMASK))

// /dev/kvm: MISC_MAJOR (10), KVM_MINOR (232) — stable UAPI constants.
#define JG_MISC_MAJOR 10
#define JG_KVM_MINOR 232

SEC("lsm/file_open")
int BPF_PROG(jg_file_open, struct file *file)
{
    // Cheap common-case bail: only character-device opens of /dev/kvm proceed.
    // For regular files i_rdev is 0, so this excludes ~every open in two reads.
    struct inode *inode = BPF_CORE_READ(file, f_inode);
    if (!inode) {
        return 0;
    }
    dev_t rdev = BPF_CORE_READ(inode, i_rdev);
    if (JG_MAJOR(rdev) != JG_MISC_MAJOR || JG_MINOR(rdev) != JG_KVM_MINOR) {
        return 0;
    }

    // It is /dev/kvm; deny iff this task is in governed scope (and not audit-only).
    return jg_governed_floor_deny();
}

char LICENSE_file_open[] SEC("license") = "GPL";
