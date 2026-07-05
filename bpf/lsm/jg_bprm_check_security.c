// SPDX-License-Identifier: GPL-2.0
//
// bpf/lsm/jg_bprm_check_security.c — Jinn Guard LSM hook for execve

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "jg_common.h"
#include "../common/maps.h"

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);
    __type(value, struct jg_verdict_payload);
} verdicts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct jg_path_key);
    __type(value, __u8);
} allowed_exec_paths SEC(".maps");

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


SEC("lsm.s/bprm_check_security")
int BPF_PROG(jg_bprm_check_security, struct linux_binprm *bprm) {
    // Pass ungoverned tasks (e.g. the operator's desktop) straight through with
    // no decision and no telemetry. Only the configured cgroup is enforced.
    if (!jg_in_governed_scope(&governed_scope)) {
        return 0;
    }
    int audit_only = jg_audit_only_enabled(&runtime_controls);
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u64 cookie = pid_tgid ^ bpf_ktime_get_ns();

    struct jg_request *req = bpf_ringbuf_reserve(&requests, sizeof(*req), 0);
    if (!req) {
        // barrier_var forces a real branch so each exit returns a
        // verifier-boundable constant (matches socket_connect/sendmsg; B1).
        int deny = !audit_only;
        barrier_var(deny);
        if (deny) {
            return -JG_EPERM;
        }
        return 0;
    }
    __builtin_memset(req, 0, sizeof(*req));

    req->cookie = cookie;
    req->pid = pid;
    req->ppid = jg_get_ppid();
    req->type = REQ_EXECVE;
    req->source_program = JG_SRC_BPRM_CHECK_SECURITY;
    const char *filename = 0;
    bpf_core_read(&filename, sizeof(filename), &bprm->filename);
    bpf_probe_read_kernel_str(req->resource_path, sizeof(req->resource_path), filename);
    struct jg_path_key path_key;
    jg_copy_path_key(&path_key, req->resource_path);
    __u8 *allowed = bpf_map_lookup_elem(&allowed_exec_paths, &path_key);
    int decision = (allowed && *allowed) ? 0 : -JG_EPERM;

    bpf_ringbuf_submit(req, 0);

    // barrier_var forces a real branch so each exit returns a verifier-boundable
    // literal — prevents a future clang from lowering `audit_only ? 0 : decision`
    // to an unbounded BPF_NEG at exit (the B1c failure mode). Matches socket_connect.
    int deny = !audit_only && decision != 0;
    barrier_var(deny);
    if (deny)
        return -JG_EPERM;
    return 0;
}

char LICENSE_bprm_check_security[] SEC("license") = "GPL";
