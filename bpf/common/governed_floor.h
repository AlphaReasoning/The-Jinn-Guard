/* SPDX-License-Identifier: GPL-2.0
 *
 * bpf/common/governed_floor.h — shared maps + deny helper for pure kernel-floor
 * "deny in governed scope" LSM hooks that make no user-space round-trip
 * (JG #50: mount / pivot_root / move_mount nesting primitives).
 *
 * Each including object gets its own loader-populated map instances; nothing is
 * pinned or shared. Include AFTER jg_common.h (for jg_in_governed_scope,
 * jg_audit_only_enabled, JG_EPERM and struct jg_verdict_payload).
 */
#pragma once

// Present only to satisfy the uniform loader (load_lsm_object requires a
// `verdicts` map in every LSM object); these floor hooks make no round-trip.
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

// Deny-by-default-in-governed-scope verdict: -JG_EPERM to deny, 0 to allow.
// Ungoverned tasks (and the whole host outside the governed cgroup subtree) are
// passed straight through; safe-mode / audit-only downgrades to observe-only.
static __always_inline int jg_governed_floor_deny(void)
{
    if (!jg_in_governed_scope(&governed_scope)) {
        return 0;
    }
    if (jg_audit_only_enabled(&runtime_controls)) {
        return 0;
    }
    return -JG_EPERM;
}
