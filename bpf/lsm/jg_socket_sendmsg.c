// SPDX-License-Identifier: GPL-2.0
//
// bpf/lsm/jg_socket_sendmsg.c — Jinn Guard LSM hook for socket_sendmsg

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
    __type(key, __u32);
    __type(value, __u8);
} ipv4_denylist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct jg_ipv6_key);
    __type(value, __u8);
} ipv6_denylist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u8);
} ipv4_allowlist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct jg_ipv6_key);
    __type(value, __u8);
} ipv6_allowlist SEC(".maps");

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


SEC("lsm.s/socket_sendmsg")
int BPF_PROG(jg_socket_sendmsg, struct socket *sock, struct msghdr *msg, int size) {
    // Pass ungoverned tasks (e.g. the operator's desktop) straight through with
    // no decision and no telemetry. Only the configured cgroup is enforced.
    if (!jg_in_governed_scope(&governed_scope)) {
        return 0;
    }
    int audit_only = jg_audit_only_enabled(&runtime_controls);
    // `struct socket.type` is a 2-byte `short`; reading sizeof(int)=4 bytes pulls
    // in adjacent padding and can make the gate below fail OPEN. Match the field
    // width exactly. Latent here (UDP sockets happened to zero-pad), real on
    // socket_connect. (JG-ADV-2026-004)
    short sock_type = 0;
    struct sockaddr *address = 0;
    __u16 family = 0;

    bpf_core_read(&sock_type, sizeof(sock_type), &sock->type);
    if (sock_type != SOCK_DGRAM) {
        return 0;
    }

    bpf_core_read(&address, sizeof(address), &msg->msg_name);
    if (address == NULL) {
        return 0;
    }
    bpf_core_read(&family, sizeof(family), &address->sa_family);

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u64 cookie = pid_tgid ^ bpf_ktime_get_ns();

    struct jg_request *req = bpf_ringbuf_reserve(&requests, sizeof(*req), 0);
    if (!req) {
        // barrier_var prevents clang -O2 from lowering `cond ? -EPERM : 0` to
        // `-(cond & 1)` (BPF_NEG), whose result the verifier cannot bound to
        // [-4095, 0] at exit (JG-ADV-2026-004 pattern; matches socket_connect).
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
    req->type = REQ_SENDMSG;
    req->source_program = JG_SRC_SOCKET_SENDMSG;
    req->family = family;
    int denied = 0;
    int default_deny = jg_connect_default_deny_enabled(&runtime_controls);

    switch (family) {
    case AF_INET: {
        struct sockaddr_in *sa = (struct sockaddr_in *)address;
        bpf_core_read(&req->dest.v4.addr, sizeof(req->dest.v4.addr), &sa->sin_addr.s_addr);
        bpf_core_read(&req->dest.v4.port, sizeof(req->dest.v4.port), &sa->sin_port);
        __u8 *entry = bpf_map_lookup_elem(&ipv4_denylist, &req->dest.v4.addr);
        if (entry && *entry) {
            denied = 1;
        } else if (default_deny && !jg_ipv4_is_loopback(req->dest.v4.addr)) {
            __u8 *allow = bpf_map_lookup_elem(&ipv4_allowlist, &req->dest.v4.addr);
            if (!(allow && *allow)) {
                denied = 1;
            }
        }
        break;
    }
    case AF_INET6: {
        struct sockaddr_in6 *sa = (struct sockaddr_in6 *)address;
        bpf_core_read(&req->dest.v6.addr, sizeof(req->dest.v6.addr), &sa->sin6_addr);
        bpf_core_read(&req->dest.v6.port, sizeof(req->dest.v6.port), &sa->sin6_port);
        
        struct jg_ipv6_key key;
        __builtin_memcpy(key.addr, req->dest.v6.addr, sizeof(key.addr));
        __u8 *entry = bpf_map_lookup_elem(&ipv6_denylist, &key);
        if (entry && *entry) {
            denied = 1;
        } else if (default_deny && !jg_ipv6_is_loopback(req->dest.v6.addr)) {
            __u8 *allow = bpf_map_lookup_elem(&ipv6_allowlist, &key);
            if (!(allow && *allow)) {
                denied = 1;
            }
        }
        break;
    }
    default:
        bpf_ringbuf_discard(req, 0);
        return 0;
    }

    bpf_ringbuf_submit(req, 0);

    // barrier_var forces a real branch so each exit returns a verifier-boundable
    // literal. Without it clang -O2 lowers `denied ? -EPERM : 0` to an unbounded
    // BPF_NEG, and the verifier rejects the program at exit ("R0 has unknown
    // scalar value should have been in [-4095, 0]"). Matches jg_socket_connect (B1).
    int deny = !audit_only && denied;
    barrier_var(deny);
    if (deny)
        return -JG_EPERM;
    return 0;
}

char LICENSE_socket_sendmsg[] SEC("license") = "GPL";
