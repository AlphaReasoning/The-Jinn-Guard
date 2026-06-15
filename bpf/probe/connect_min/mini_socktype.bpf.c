// Probe v2 = the minimal deny-127.0.0.2 hook PLUS exactly the real connect
// hook's `sock->type` read and its fail-OPEN gate. Everything else is identical
// to mini.bpf.c (which enforces 1500/1500 deterministically). If THIS version
// leaks under a non-blocking-connect burst, the residual fail-open is the
// sock->type read / fail-open gate, not anything else.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef SOCK_STREAM
#define SOCK_STREAM 1
#endif
#ifndef SOCK_DGRAM
#define SOCK_DGRAM 2
#endif

#define DENIED_ADDR 0x0200007f // 127.0.0.2

SEC("lsm.s/socket_connect")
int BPF_PROG(deny_one, struct socket *sock, struct sockaddr *address, int addrlen, int ret)
{
    // The ONLY addition vs mini.bpf.c: read sock->type and fail OPEN on a
    // type we don't recognise — exactly like jg_socket_connect.c.
    int sock_type = 0;
    bpf_core_read(&sock_type, sizeof(sock_type), &sock->type);
    if (sock_type != SOCK_STREAM && sock_type != SOCK_DGRAM)
        return ret; // fail-open gate under test

    __u16 family = 0;
    bpf_core_read(&family, sizeof(family), &address->sa_family);
    if (family != AF_INET)
        return ret;
    struct sockaddr_in *sa = (struct sockaddr_in *)address;
    __u32 addr = 0;
    bpf_core_read(&addr, sizeof(addr), &sa->sin_addr.s_addr);
    if (addr == DENIED_ADDR)
        return -1; // -EPERM
    return ret;
}

char _license[] SEC("license") = "GPL";
