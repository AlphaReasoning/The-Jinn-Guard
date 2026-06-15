// Minimal standalone BPF-LSM socket_connect reproducer.
// Denies connect() to 127.0.0.2 with a hardcoded, race-free, maps-free check.
// Purpose: determine whether a kernel honors a sleepable socket_connect -EPERM
// deterministically (isolating Jinn Guard's userspace from the kernel path).
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#ifndef AF_INET
#define AF_INET 2
#endif

// 127.0.0.2 as stored in sockaddr_in.sin_addr.s_addr (network order, x86 LE).
#define DENIED_ADDR 0x0200007f

SEC("lsm.s/socket_connect")
int BPF_PROG(deny_one, struct socket *sock, struct sockaddr *address, int addrlen, int ret)
{
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
