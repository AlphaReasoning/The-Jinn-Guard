// SPDX-License-Identifier: GPL-2.0
//
// bpf/lsm/jg_inode_create.c — Jinn Guard LSM hook for file creation

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
} denied_basenames SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, __u8);
} denied_dir_inodes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} runtime_controls SEC(".maps");

static __always_inline int jg_inode_basename_denied(const char *path)
{
    struct jg_path_key key = {};

    __builtin_memcpy(key.path, path, sizeof(key.path));
    __u8 *entry = bpf_map_lookup_elem(&denied_basenames, &key);
    return entry && *entry;
}

static __always_inline int jg_inode_dir_denied(struct inode *dir)
{
    __u64 ino = 0;

    if (!dir) {
        return 0;
    }

    bpf_probe_read_kernel(&ino, sizeof(ino), JG_CORE_FIELD_PTR(dir, struct inode, i_ino));
    __u8 *entry = bpf_map_lookup_elem(&denied_dir_inodes, &ino);
    return entry && *entry;
}


SEC("lsm.s/inode_create")
int BPF_PROG(jg_inode_create, struct inode *dir, struct dentry *dentry, umode_t mode) {
    int audit_only = jg_audit_only_enabled(&runtime_controls);

    if (!JG_S_ISREG(mode)) {
        return 0;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u64 cookie = pid_tgid ^ bpf_ktime_get_ns();
    char resource_path[JG_MAX_RESOURCE_LEN] = {};

    jg_read_dentry_basename(dentry, resource_path, sizeof(resource_path));
    int decision = (jg_inode_dir_denied(dir) || jg_inode_basename_denied(resource_path))
        ? -JG_EPERM
        : 0;

    struct jg_request *req = bpf_ringbuf_reserve(&requests, sizeof(*req), 0);
    if (!req) {
        return audit_only ? 0 : -JG_EPERM;
    }
    __builtin_memset(req, 0, sizeof(*req));

    req->cookie = cookie;
    req->pid = pid;
    req->type = REQ_INODE_CREATE;
    __builtin_memcpy(req->resource_path, resource_path, sizeof(req->resource_path));

    bpf_ringbuf_submit(req, 0);
    return audit_only ? 0 : decision;
}

char LICENSE_inode_create[] SEC("license") = "GPL";
