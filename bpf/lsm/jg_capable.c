// SPDX-License-Identifier: GPL-2.0
//
// bpf/lsm/jg_capable.c — Jinn Guard LSM hook for capability checks (JG #53).
//
// Restricts unprivileged user-namespace nesting for governed agents. The escape
// it closes: a confined agent calls unshare(CLONE_NEWUSER), which grants it full
// capabilities *inside* the new user namespace, and then uses CAP_SYS_ADMIN
// there to mount/pivot/build a nested container that the host LSM scope would
// otherwise not reach.
//
// We deny a small set of escalation/integrity capabilities when they are
// exercised inside a NON-init user namespace (level > 0) by a task in the
// governed cgroup subtree. The init-user-ns fast path (level == 0) returns
// immediately, so this hook — which fires on every capable() check host-wide —
// adds only a single field read on the overwhelmingly common path.
//
// exec of container-runtime binaries is already denied by the bprm allowlist;
// this is the in-process (no-exec) layer. #50 adds the mount/namespace hooks.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "jg_common.h"
#include "../common/maps.h"

// Present only to satisfy the uniform loader (load_lsm_object requires a
// `verdicts` map in every LSM object); this hook makes no userspace round-trip.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);
    __type(value, struct jg_verdict_payload);
} verdicts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} runtime_controls SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} governed_scope SEC(".maps");

// Escalation / integrity capabilities denied inside a nested user namespace.
// Values are stable UAPI capability numbers (linux/capability.h).
#define JG_CAP_SYS_MODULE 16
#define JG_CAP_SYS_RAWIO  17
#define JG_CAP_SYS_PTRACE 19
#define JG_CAP_SYS_ADMIN  21
#define JG_CAP_SYS_BOOT   22
#define JG_CAP_MKNOD      27

static __always_inline int jg_cap_is_denylisted(int cap)
{
    switch (cap) {
    case JG_CAP_SYS_MODULE:
    case JG_CAP_SYS_RAWIO:
    case JG_CAP_SYS_PTRACE:
    case JG_CAP_SYS_ADMIN:
    case JG_CAP_SYS_BOOT:
    case JG_CAP_MKNOD:
        return 1;
    default:
        return 0;
    }
}

SEC("lsm/capable")
int BPF_PROG(jg_capable, const struct cred *cred, struct user_namespace *ns,
             int cap, unsigned int opts)
{
    if (!ns) {
        return 0;
    }
    // Fast path: capabilities in the init user namespace (level 0) are none of
    // our business. This is the hot path for nearly every capable() check.
    int level = BPF_CORE_READ(ns, level);
    if (level == 0) {
        return 0;
    }
    // Nested user namespace: only deny the escalation/integrity capabilities
    // that enable further nesting; benign caps still pass so legitimate
    // unprivileged-userns use is not gratuitously broken.
    if (!jg_cap_is_denylisted(cap)) {
        return 0;
    }
    if (!jg_in_governed_scope(&governed_scope)) {
        return 0;
    }
    if (jg_audit_only_enabled(&runtime_controls)) {
        return 0;
    }
    return -JG_EPERM;
}

char LICENSE_capable[] SEC("license") = "GPL";
