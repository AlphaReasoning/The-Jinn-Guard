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
#define JG_CONTROL_AUDIT_ONLY 1

#define JG_CORE_FIELD_PTR(ptr, type, field) \
    ((const void *)((const char *)(ptr) + bpf_core_field_offset(type, field)))

#define jg_audit_only_enabled(runtime_controls) ({                 \
    __u32 __jg_control_key = 0;                                    \
    __u32 *__jg_control_value =                                    \
        bpf_map_lookup_elem((runtime_controls), &__jg_control_key); \
    __jg_control_value && (*__jg_control_value & JG_CONTROL_AUDIT_ONLY); \
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

// Maximum number of parent directories walked when resolving a full path, and
// the per-component scratch length. Bounded so the BPF verifier accepts the
// unrolled walk; very deep paths are truncated on the left (the basename and
// directory-inode checks still apply, so this is never weaker than basename).
#define JG_PATH_MAX_DEPTH 17
#define JG_PATH_COMP_LEN 40

// Resolve the absolute path of `dentry` into `out` (CVE-2026-002). Walks
// `d_parent` up to JG_PATH_MAX_DEPTH levels, prepending "/component" into a
// scratch buffer from the right, then left-justifies the result into `out`.
// Falls back to the basename if the walk yields nothing. Every dynamic buffer
// index is masked into [0, JG_MAX_RESOURCE_LEN) so the verifier can prove the
// accesses are in bounds. JG_MAX_RESOURCE_LEN must be a power of two.
static __always_inline void jg_read_dentry_path(
    struct dentry *dentry,
    char *out,
    __u32 out_size)
{
    jg_clear_resource(out);
    if (!dentry) {
        return;
    }

    char scratch[JG_MAX_RESOURCE_LEN];
#pragma unroll
    for (int i = 0; i < JG_MAX_RESOURCE_LEN; i++) {
        scratch[i] = '\0';
    }

    int wpos = JG_MAX_RESOURCE_LEN; // exclusive end; decremented before a write
    struct dentry *d = dentry;
    struct dentry *parent = 0;
    int components = 0;

#pragma unroll
    for (int depth = 0; depth < JG_PATH_MAX_DEPTH; depth++) {
        bpf_probe_read_kernel(
            &parent, sizeof(parent),
            JG_CORE_FIELD_PTR(d, struct dentry, d_parent));

        const unsigned char *name_ptr = 0;
        bpf_probe_read_kernel(
            &name_ptr, sizeof(name_ptr),
            JG_CORE_FIELD_PTR(d, struct dentry, d_name.name));

        char comp[JG_PATH_COMP_LEN];
#pragma unroll
        for (int i = 0; i < JG_PATH_COMP_LEN; i++) {
            comp[i] = '\0';
        }
        int clen = 0;
        if (name_ptr) {
            clen = bpf_probe_read_kernel_str(comp, sizeof(comp), name_ptr);
        }

        // A usable component has clen > 1 (skips empty names and the root
        // dentry, whose d_name.name is "/" giving clen == 2, comp[0] == '/').
        int usable = (clen > 1) && !(comp[0] == '/' && clen == 2);
        if (usable) {
            int n = clen - 1; // characters excluding the trailing NUL
            if (n > JG_PATH_COMP_LEN - 1) {
                n = JG_PATH_COMP_LEN - 1;
            }
            // Prepend comp[0..n-1] (rightmost char first), then a leading '/'.
#pragma unroll
            for (int k = JG_PATH_COMP_LEN - 1; k >= 0; k--) {
                if (k < n && wpos > 1) {
                    wpos--;
                    scratch[wpos & (JG_MAX_RESOURCE_LEN - 1)] = comp[k];
                }
            }
            if (wpos > 1) {
                wpos--;
                scratch[wpos & (JG_MAX_RESOURCE_LEN - 1)] = '/';
            }
            components++;
        }

        if (d == parent || parent == 0) {
            break;
        }
        d = parent;
    }

    if (components == 0) {
        jg_read_dentry_basename(dentry, out, out_size);
        return;
    }

    // Left-justify scratch[wpos .. JG_MAX_RESOURCE_LEN-1] into out. A bounded
    // (non-unrolled) loop: the verifier proves 0 <= i < JG_MAX_RESOURCE_LEN.
    int start = wpos & (JG_MAX_RESOURCE_LEN - 1);
    int oi = 0;
    for (int i = 0; i < JG_MAX_RESOURCE_LEN; i++) {
        if (i >= start && oi < (int)out_size - 1) {
            out[oi & (JG_MAX_RESOURCE_LEN - 1)] = scratch[i];
            oi++;
        }
    }
    out[oi & (JG_MAX_RESOURCE_LEN - 1)] = '\0';
}

// Copy the basename (text after the final '/') of a full `path` into `key`,
// so the in-kernel basename denylist keeps working now that hooks report the
// full resolved path. Dynamic reads of `path` are masked into bounds.
static __always_inline void jg_basename_key(struct jg_path_key *key, const char *path)
{
    __builtin_memset(key, 0, sizeof(*key));

    int base = 0; // index of the first basename character
#pragma unroll
    for (int i = 0; i < JG_MAX_RESOURCE_LEN; i++) {
        char c = path[i];
        if (c == '\0') {
            break;
        }
        if (c == '/') {
            base = i + 1;
        }
    }

#pragma unroll
    for (int i = 0; i < JG_MAX_RESOURCE_LEN; i++) {
        if (base + i >= JG_MAX_RESOURCE_LEN) {
            break;
        }
        char c = path[(base + i) & (JG_MAX_RESOURCE_LEN - 1)];
        key->path[i & (JG_MAX_RESOURCE_LEN - 1)] = c;
        if (c == '\0') {
            break;
        }
    }
}
