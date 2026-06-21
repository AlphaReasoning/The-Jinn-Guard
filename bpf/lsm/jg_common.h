/* SPDX-License-Identifier: GPL-2.0
 *
 * bpf/lsm/jg_common.h — Common types for Jinn Guard LSM hooks.
 */
#pragma once

/*
 * LSM CO-RE programs include vmlinux.h before this header. Keep this file free
 * of system kernel headers; __u* typedefs are provided by vmlinux.h.
 */

#ifndef AF_UNIX
#define AF_UNIX 1
#endif

#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef AF_INET6
#define AF_INET6 10
#endif

#ifndef SOCK_STREAM
#define SOCK_STREAM 1
#endif

#ifndef SOCK_DGRAM
#define SOCK_DGRAM 2
#endif

#ifndef JG_EPERM
#define JG_EPERM 1
#endif

#ifndef S_IFMT
#define S_IFMT 00170000
#endif

#ifndef S_IFREG
#define S_IFREG 0100000
#endif

#define JG_S_ISREG(mode) (((mode) & S_IFMT) == S_IFREG)

#define JG_MAX_RESOURCE_LEN 128
#define JG_PAYLOAD_PREVIEW_LEN 64
#define JG_MAX_UNIX_PATH 108
#define JG_MAX_POLICY_PATHS 8

// runtime_controls is a single-slot u32 bitfield (key 0) shared by all hooks.
#define JG_CONTROL_AUDIT_ONLY 1            // bit 0: observe-only, never deny
#define JG_CONTROL_CONNECT_DEFAULT_DENY 2  // bit 1: deny non-allowlisted egress

#define JG_CORE_FIELD_PTR(ptr, type, field) \
    ((const void *)((const char *)(ptr) + bpf_core_field_offset(type, field)))

#define jg_audit_only_enabled(runtime_controls) ({                 \
    __u32 __jg_control_key = 0;                                    \
    __u32 *__jg_control_value =                                    \
        bpf_map_lookup_elem((runtime_controls), &__jg_control_key); \
    __jg_control_value && (*__jg_control_value & JG_CONTROL_AUDIT_ONLY); \
})

// Bit 1 of runtime_controls: when set, governed-scope network egress is
// default-deny (allow only explicitly allow-listed destinations). Opt-in, so
// the historical denylist-only behavior is unchanged when the bit is clear.
#define jg_connect_default_deny_enabled(runtime_controls) ({       \
    __u32 __jg_dd_key = 0;                                         \
    __u32 *__jg_dd_value =                                         \
        bpf_map_lookup_elem((runtime_controls), &__jg_dd_key);    \
    __jg_dd_value && (*__jg_dd_value & JG_CONTROL_CONNECT_DEFAULT_DENY); \
})

// True for 127.0.0.0/8. `addr` is the raw 4 bytes of sin_addr.s_addr read into a
// host u32; the first octet is therefore the low byte on every supported arch.
// Loopback is exempt from default-deny so local services / the agent's own
// localhost calls are never broken by enabling egress lockdown.
static __always_inline int jg_ipv4_is_loopback(__u32 addr)
{
    return (addr & 0xFF) == 127;
}

// Cgroup-scoped enforcement (the structural anti-lockout guarantee).
//
// The `governed_scope` array holds a single u64 at key 0:
//   * 0  (JG_SCOPE_GLOBAL) or map missing -> govern every task on the host
//     (the historical/deployed default; behavior is unchanged when nobody
//     configures a scope).
//   * non-zero -> a specific cgroup v2 id (the kernfs id returned by
//     bpf_get_current_cgroup_id(), == the value name_to_handle_at() reports
//     for the cgroup directory). ONLY tasks in that cgroup are subject to
//     allow/deny; every other task is passed straight through (return 0).
//
// This lets armed enforcement be confined to a dedicated agent/test cgroup so
// the operator's own desktop is never denied — the previous source of lockouts.
#define JG_SCOPE_KEY 0
#define JG_SCOPE_GLOBAL 0ULL

#define jg_in_governed_scope(governed_scope) ({                    \
    __u32 __jg_scope_key = JG_SCOPE_KEY;                           \
    __u64 *__jg_scope_value =                                      \
        bpf_map_lookup_elem((governed_scope), &__jg_scope_key);   \
    int __jg_in_scope = 1;                                         \
    if (__jg_scope_value && *__jg_scope_value != JG_SCOPE_GLOBAL) { \
        __jg_in_scope =                                            \
            (bpf_get_current_cgroup_id() == *__jg_scope_value);   \
    }                                                             \
    __jg_in_scope;                                                 \
})

struct jg_path_key {
    char path[JG_MAX_RESOURCE_LEN];
};

// Decision verdict from user-space.
enum jg_verdict {
    VERDICT_UNKNOWN = 0,
    VERDICT_ALLOW   = 1,
    VERDICT_DENY    = 2,
};

// Type of operation being requested.
enum jg_request_type {
    REQ_CONNECT        = 0,
    REQ_SENDMSG        = 1,
    REQ_EXECVE         = 2,
    REQ_INODE_CREATE   = 3,
    REQ_INODE_UNLINK   = 4,
};

enum jg_source_program {
    JG_SRC_INODE_CREATE = 1,
    JG_SRC_INODE_UNLINK = 2,
    JG_SRC_BPRM_CHECK_SECURITY = 3,
    JG_SRC_SOCKET_CONNECT = 4,
    JG_SRC_SOCKET_SENDMSG = 5,
};

// Request from BPF to user-space, sent via ring buffer.
struct jg_request {
    __u64 cookie;
    __u32 pid;
    enum jg_request_type type;
    __u16 family;

    // For execve, inode ops - the resource path.
    char resource_path[JG_MAX_RESOURCE_LEN];
    __u8 __pad_after_resource[2];

    // For network ops - destination details.
    union {
        struct {
            __u32 addr;
            __u16 port;
        } v4;
        struct {
            __u8  addr[16];
            __u16 port;
        } v6;
        char path[JG_MAX_UNIX_PATH];
    } dest;

    // For sendmsg, a preview of the outgoing payload.
    __u8 payload_preview[JG_PAYLOAD_PREVIEW_LEN];

    // Stable route back to the object-local verdict map.
    __u32 source_program;
};

// Verdict from user-space to BPF, sent via a hash map.
struct jg_verdict_payload {
    __u64 cookie;
    enum jg_verdict verdict;
};

static __always_inline int jg_path_equals(const char *left, const char *right)
{
#pragma unroll
    for (int i = 0; i < JG_MAX_RESOURCE_LEN; i++) {
        if (left[i] != right[i]) {
            return 0;
        }
        if (left[i] == '\0') {
            return 1;
        }
    }
    return 1;
}

static __always_inline int jg_path_has_prefix(const char *path, const char *prefix)
{
#pragma unroll
    for (int i = 0; i < JG_MAX_RESOURCE_LEN; i++) {
        if (prefix[i] == '\0') {
            return 1;
        }
        if (path[i] == '\0') {
            return 0;
        }
        if (path[i] != prefix[i]) {
            return 0;
        }
    }
    return 1;
}

static __always_inline void jg_copy_path_key(struct jg_path_key *key, const char *path)
{
    __builtin_memset(key, 0, sizeof(*key));
#pragma unroll
    for (int i = 0; i < JG_MAX_RESOURCE_LEN; i++) {
        key->path[i] = path[i];
        if (path[i] == '\0') {
            break;
        }
    }
}

static __always_inline void jg_clear_resource(char *out)
{
#pragma unroll
    for (int i = 0; i < JG_MAX_RESOURCE_LEN; i++) {
        out[i] = '\0';
    }
}

static __always_inline void jg_read_dentry_basename(
    struct dentry *dentry,
    char *out,
    __u32 out_size)
{
    const unsigned char *name = 0;

    jg_clear_resource(out);

    if (!dentry) {
        return;
    }

    bpf_probe_read_kernel(
        &name,
        sizeof(name),
        JG_CORE_FIELD_PTR(dentry, struct dentry, d_name.name));
    if (name) {
        bpf_probe_read_kernel_str(out, out_size, name);
    }
}

// Maximum directory depth walked when resolving a path. Kept small so the BPF
// verifier accepts the program well under its instruction budget; paths deeper
// than this fall back to the basename (the directory-inode check still applies,
// so this is never weaker than basename-only).
#define JG_PATH_MAX_DEPTH 12
#define JG_PATH_COMP_LEN 40

// Resolve the absolute path of `dentry` into `out` (JG-ADV-2026-002). Two cheap
// passes keep verifier work tiny: first collect the dentry chain leaf->root as
// bare pointers (no string work), then write each component root->leaf with a
// single bpf_probe_read_kernel_str per level. A guard before each write proves
// the destination is in bounds, so there are no nested copy loops, no scratch
// buffer, and no index masking. Falls back to the basename for paths deeper
// than JG_PATH_MAX_DEPTH so a partial path is never emitted.
//
// Mount boundaries: the inode_create/unlink hooks receive only a dentry (no
// vfsmount), so the walk stops at the dentry-tree root of the file's own mount.
// On the root filesystem this is the true absolute path (/etc, /usr, /opt, ...).
// For a file on a sub-mount (e.g. a tmpfs at /tmp) the result is relative to
// that mount's root (/tmp/x -> /x). Crossing mounts needs path-family LSM hooks
// or bpf_d_path; tracked as a known limitation.
static __always_inline void jg_read_dentry_path(
    struct dentry *dentry,
    char *out,
    __u32 out_size)
{
    jg_clear_resource(out);
    if (!dentry) {
        return;
    }

    struct dentry *chain[JG_PATH_MAX_DEPTH];
    int depth = 0;
    int reached_root = 0;
    struct dentry *d = dentry;
    struct dentry *parent = 0;

#pragma unroll
    for (int i = 0; i < JG_PATH_MAX_DEPTH; i++) {
        chain[i] = d;
        depth = i + 1;
        bpf_probe_read_kernel(
            &parent, sizeof(parent),
            JG_CORE_FIELD_PTR(d, struct dentry, d_parent));
        if (parent == 0 || parent == d) {
            reached_root = 1;
            break;
        }
        d = parent;
    }

    if (!reached_root) {
        jg_read_dentry_basename(dentry, out, out_size);
        return;
    }

    // Write root -> leaf, skipping the root dentry itself (its name is "/").
    int off = 0;
#pragma unroll
    for (int i = JG_PATH_MAX_DEPTH - 1; i >= 0; i--) {
        if (i >= depth - 1) {
            continue; // out of range, or the root component
        }
        struct dentry *cur = chain[i];
        const unsigned char *name = 0;
        bpf_probe_read_kernel(
            &name, sizeof(name),
            JG_CORE_FIELD_PTR(cur, struct dentry, d_name.name));
        if (name == 0) {
            continue;
        }
        // Guarantee room for '/' plus a full component so every byte written is
        // provably in bounds (off stays <= MAX - COMP - 2 here).
        if (off > JG_MAX_RESOURCE_LEN - JG_PATH_COMP_LEN - 2) {
            break;
        }
        long n = bpf_probe_read_kernel_str(&out[off + 1], JG_PATH_COMP_LEN, name);
        if (n > 1) {
            out[off] = '/';
            off += 1 + (int)(n - 1);
        }
    }

    if (off <= 0) {
        jg_read_dentry_basename(dentry, out, out_size);
        return;
    }
    if (off >= (int)out_size) {
        off = (int)out_size - 1;
    }
    out[off] = '\0';
}
