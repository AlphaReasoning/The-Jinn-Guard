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
