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
#define JG_CONTROL_UNIX_DEFAULT_DENY 4     // bit 2: deny non-allowlisted AF_UNIX

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

// Bit 2 of runtime_controls: when set, governed-scope AF_UNIX connects are
// default-deny — only explicitly allow-listed socket paths (plus the Jinn Guard
// control socket, which the daemon always allow-lists for anti-lockout) are
// permitted; everything else, including abstract-namespace sockets, is denied.
// Opt-in and independent of the IPv4 default-deny bit, so enabling network
// default-deny does not silently sever the agent's local IPC (JG #56).
#define jg_unix_default_deny_enabled(runtime_controls) ({          \
    __u32 __jg_ud_key = 0;                                         \
    __u32 *__jg_ud_value =                                         \
        bpf_map_lookup_elem((runtime_controls), &__jg_ud_key);    \
    __jg_ud_value && (*__jg_ud_value & JG_CONTROL_UNIX_DEFAULT_DENY); \
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
//     for the cgroup directory). Tasks in that cgroup OR any descendant cgroup
//     (the whole subtree) are subject to allow/deny; every other task is passed
//     straight through (return 0).
//
// This lets armed enforcement be confined to a dedicated agent/test cgroup so
// the operator's own desktop is never denied — the previous source of lockouts.
#define JG_SCOPE_KEY 0
#define JG_SCOPE_GLOBAL 0ULL

// Maximum cgroup-v2 hierarchy depth walked when testing subtree membership.
// bpf_get_current_ancestor_cgroup_id() returns 0 for levels deeper than the
// task's own cgroup, so a governed cgroup at any absolute depth < this bound is
// always matched; the cap only sets how many cheap helper calls an ungoverned
// task costs. Generous — agent cgroups sit only a few levels under the root.
#define JG_CGROUP_MAX_DEPTH 16

// Un-sheddable cgroup-subtree membership test (JG #49).
//
// Returns 1 if the current task is governed. Global scope (id 0 or map missing)
// governs everyone. Otherwise the task is governed iff the configured cgroup id
// is its own cgroup OR appears anywhere in its ancestor chain — i.e. the task
// is anywhere in the governed cgroup *subtree*. Matching the whole subtree (not
// just the exact id) is what makes the scope un-sheddable: a governed agent
// that creates or migrates into a child cgroup within its delegated subtree
// stays governed. Escaping requires moving to a cgroup OUTSIDE the subtree,
// which needs write access to a foreign cgroup.procs that a confined agent does
// not have (and that #50/#53 further deny).
//
// Anti-lockout is preserved exactly: global scope governs all with no walk, and
// a task outside the subtree is passed straight through as before.
static __always_inline int jg_in_governed_scope(void *governed_scope)
{
    __u32 scope_key = JG_SCOPE_KEY;
    __u64 *scope = bpf_map_lookup_elem(governed_scope, &scope_key);
    if (!scope || *scope == JG_SCOPE_GLOBAL) {
        return 1;
    }
    // Fast path: the task is directly in the governed cgroup.
    if (bpf_get_current_cgroup_id() == *scope) {
        return 1;
    }
    // Subtree path: is the governed cgroup an ancestor at any level?
#pragma unroll
    for (int lvl = 0; lvl < JG_CGROUP_MAX_DEPTH; lvl++) {
        if (bpf_get_current_ancestor_cgroup_id(lvl) == *scope) {
            return 1;
        }
    }
    return 0;
}

struct jg_path_key {
    char path[JG_MAX_RESOURCE_LEN];
};

// Collision-free identity of a directory inode: the superblock device id PLUS
// the inode number. i_ino alone is only unique *within* a superblock, so it can
// collide across mounts/filesystems; pairing it with i_sb->s_dev makes the
// denied-directory match exact and immune to mount/bind/pivot_root remapping
// (JG #52). Both fields are __u64 so the 16-byte key has no internal padding
// (a hashed BPF map key must be fully initialized — no padding holes).
struct jg_inode_key {
    __u64 dev;
    __u64 ino;
};

// Precise per-file denial identity: the parent directory's (dev, ino) PLUS the
// file's basename. Lets a denied *file* path (e.g. /etc/passwd) match only that
// name in that exact directory, instead of the basename anywhere in scope (which
// over-blocks). Layout is (u64, u64, char[128]) = 144 bytes with no padding hole,
// so the hashed key is fully defined. Must match `DirFileKey` in ebpf_monitor.rs.
struct jg_dir_file_key {
    __u64 dev;
    __u64 ino;
    char name[JG_MAX_RESOURCE_LEN];
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
