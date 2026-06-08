// SPDX-License-Identifier: GPL-2.0
//
// bpf/lsm/jg_bprm_check_security.c — Jinn Guard LSM hook for execve

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "jg_common.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} requests SEC(".maps");

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


SEC("lsm.s/bprm_check_security")
int BPF_PROG(jg_bprm_check_security, struct linux_binprm *bprm) {
    int audit_only = jg_audit_only_enabled(&runtime_controls);
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u64 cookie = pid_tgid ^ bpf_ktime_get_ns();

    struct jg_request *req = bpf_ringbuf_reserve(&requests, sizeof(*req), 0);
    if (!req) {
        return audit_only ? 0 : -JG_EPERM;
    }
    __builtin_memset(req, 0, sizeof(*req));

    req->cookie = cookie;
    req->pid = pid;
    req->type = REQ_EXECVE;
    const char *filename = 0;
    bpf_core_read(&filename, sizeof(filename), &bprm->filename);
    bpf_probe_read_kernel_str(req->resource_path, sizeof(req->resource_path), filename);
    struct jg_path_key path_key;
    jg_copy_path_key(&path_key, req->resource_path);
    __u8 *allowed = bpf_map_lookup_elem(&allowed_exec_paths, &path_key);
    int decision = (allowed && *allowed) ? 0 : -JG_EPERM;

    bpf_ringbuf_submit(req, 0);
    return audit_only ? 0 : decision;
}

char LICENSE_bprm_check_security[] SEC("license") = "GPL";
