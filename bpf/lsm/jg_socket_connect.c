// SPDX-License-Identifier: GPL-2.0
//
// bpf/lsm/jg_socket_connect.c — Jinn Guard LSM hook for socket_connect

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

// #54: explicit IPv4 egress allowlist, consulted only when default-deny is on.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u8);
} ipv4_allowlist SEC(".maps");

// #55: AF_UNIX deputy-socket denylist. Keyed by the full connect path so a
// governed agent cannot reach an orchestrator/init control socket (docker.sock,
// containerd.sock, the systemd/D-Bus private sockets, libvirt, podman, crio)
// and borrow that daemon's ungoverned root authority (confused deputy).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, struct jg_path_key);
    __type(value, __u8);
} unix_denylist SEC(".maps");

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


SEC("lsm.s/socket_connect")
int BPF_PROG(jg_socket_connect, struct socket *sock, struct sockaddr *address, int addrlen) {
    // Pass ungoverned tasks (e.g. the operator's desktop) straight through with
    // no decision and no telemetry. Only the configured cgroup is enforced.
    if (!jg_in_governed_scope(&governed_scope)) {
        return 0;
    }
    int audit_only = jg_audit_only_enabled(&runtime_controls);
    // `struct socket.type` is a 2-byte `short`. Reading it into a 4-byte int and
    // copying sizeof(int)=4 bytes pulls in 2 adjacent padding bytes; when those
    // are non-zero, sock_type != SOCK_STREAM/SOCK_DGRAM and the gate below would
    // fail OPEN (allow). Match the field width exactly. (JG-ADV-2026-004)
    short sock_type = 0;
    __u16 family = 0;

    bpf_core_read(&sock_type, sizeof(sock_type), &sock->type);
    bpf_core_read(&family, sizeof(family), &address->sa_family);

    if (sock_type != SOCK_STREAM && sock_type != SOCK_DGRAM) {
        return 0;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u64 cookie = pid_tgid ^ bpf_ktime_get_ns();

    struct jg_request *req = bpf_ringbuf_reserve(&requests, sizeof(*req), 0);
    if (!req) {
        // barrier_var stops clang -O2 from lowering `cond ? -EPERM : 0` to
        // `-(cond & 1)` (BPF_NEG), whose result the verifier cannot bound to
        // [-4095, 0] at exit once it has been spilled to stack in this larger
        // program. Forcing a real branch makes each arm return a literal.
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
    req->type = REQ_CONNECT;
    req->source_program = JG_SRC_SOCKET_CONNECT;
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
            // #54: deny non-loopback IPv4 egress unless explicitly allow-listed.
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
        // #54: there is no IPv6 allowlist yet, so under default-deny IPv6 egress
        // fails closed rather than offering an un-allowlisted bypass of the v4
        // lockdown. (IPv6 allowlisting is tracked for a follow-up.)
        if (default_deny) {
            denied = 1;
        }
        break;
    }
    case AF_UNIX: {
        struct sockaddr_un *sa = (struct sockaddr_un *)address;
        bpf_probe_read_kernel_str(&req->dest.path, sizeof(req->dest.path), &sa->sun_path);
        // #55: deny connects to denylisted orchestrator/init control sockets.
        // (Pathname sockets only; an abstract socket reads as "" and is not
        // matched — documented limitation.)
        struct jg_path_key unix_key;
        jg_copy_path_key(&unix_key, req->dest.path);
        __u8 *unix_entry = bpf_map_lookup_elem(&unix_denylist, &unix_key);
        if (unix_entry && *unix_entry) {
            denied = 1;
        }
        break;
    }
    default:
        bpf_ringbuf_discard(req, 0);
        return 0;
    }

    bpf_ringbuf_submit(req, 0);
    // See the note above: barrier_var forces a real branch so each exit returns
    // a literal the verifier can bound, instead of a `-(cond & 1)` negation.
    int deny = !audit_only && denied;
    barrier_var(deny);
    if (deny) {
        return -JG_EPERM;
    }
    return 0;
}

char LICENSE_socket_connect[] SEC("license") = "GPL";
