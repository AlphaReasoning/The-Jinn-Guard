// SPDX-License-Identifier: GPL-2.0
//
// bpf/lsm/jg_inode_create.c — Jinn Guard LSM hook for file creation

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
} denied_basenames SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct jg_inode_key);
    __type(value, __u8);
} denied_dir_inodes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct jg_dir_file_key);
    __type(value, __u8);
} denied_files_in_dir SEC(".maps");

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

static __always_inline int jg_inode_basename_denied(const char *path)
{
    struct jg_path_key key = {};

    __builtin_memcpy(key.path, path, sizeof(key.path));
    __u8 *entry = bpf_map_lookup_elem(&denied_basenames, &key);
    return entry && *entry;
}

static __always_inline int jg_inode_dir_denied(struct inode *dir)
{
    struct jg_inode_key key = {};

    if (!dir) {
        return 0;
    }

    // Key on (superblock device, inode number), not i_ino alone: i_ino is only
    // unique within a superblock, so a bare-ino denylist collides across mounts.
    // The (dev, ino) identity is what the daemon resolved via stat(2) and is
    // immune to mount/bind/pivot_root path remapping (JG #52).
    key.ino = BPF_CORE_READ(dir, i_ino);
    key.dev = (__u64)BPF_CORE_READ(dir, i_sb, s_dev);
    __u8 *entry = bpf_map_lookup_elem(&denied_dir_inodes, &key);
    return entry && *entry;
}

static __always_inline int jg_inode_file_in_dir_denied(struct inode *dir, const char *name)
{
    struct jg_dir_file_key key = {};

    if (!dir) {
        return 0;
    }

    // Precise per-file match: the file's basename within its parent dir's
    // (dev, ino) identity (JG #60), so a denied file name is denied only in the
    // configured directory, not everywhere in governed scope (the basename-only
    // map remains as a fallback for entries whose parent did not resolve at load).
    key.ino = BPF_CORE_READ(dir, i_ino);
    key.dev = (__u64)BPF_CORE_READ(dir, i_sb, s_dev);
#pragma unroll
    for (int i = 0; i < JG_MAX_RESOURCE_LEN; i++) {
        key.name[i] = name[i];
        if (name[i] == '\0') {
            break;
        }
    }
    __u8 *entry = bpf_map_lookup_elem(&denied_files_in_dir, &key);
    return entry && *entry;
}


SEC("lsm.s/inode_create")
int BPF_PROG(jg_inode_create, struct inode *dir, struct dentry *dentry, umode_t mode) {
    // Pass ungoverned tasks (e.g. the operator's desktop) straight through with
    // no decision and no telemetry. Only the configured cgroup is enforced.
    if (!jg_in_governed_scope(&governed_scope)) {
        return 0;
    }
    int audit_only = jg_audit_only_enabled(&runtime_controls);

    if (!JG_S_ISREG(mode)) {
        return 0;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u64 cookie = pid_tgid ^ bpf_ktime_get_ns();
    char resource_path[JG_MAX_RESOURCE_LEN] = {};

    // Check the in-kernel denylists on the basename first (cheap, preserves the
    // existing synchronous enforcement), then resolve the full path for the
    // user-space request below (JG-ADV-2026-002).
    jg_read_dentry_basename(dentry, resource_path, sizeof(resource_path));
    int decision = (jg_inode_dir_denied(dir)
                    || jg_inode_file_in_dir_denied(dir, resource_path)
                    || jg_inode_basename_denied(resource_path))
        ? -JG_EPERM
        : 0;
    jg_read_dentry_path(dentry, resource_path, sizeof(resource_path));

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
    req->type = REQ_INODE_CREATE;
    req->source_program = JG_SRC_INODE_CREATE;
    __builtin_memcpy(req->resource_path, resource_path, sizeof(req->resource_path));

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

char LICENSE_inode_create[] SEC("license") = "GPL";
