// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "jg_events.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);
} EVENTS SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int jg_openat(struct trace_event_raw_sys_enter *ctx)
{
    struct jg_event *e;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    e = bpf_ringbuf_reserve(&EVENTS, sizeof(*e), 0);
    if (!e)
        return 0;

    e->probe_id = JG_PROBE_OPENAT;
    e->pid      = pid;
    e->denied   = 0;

    const char *filename = (const char *)BPF_CORE_READ(ctx, args[1]);
    bpf_probe_read_user_str(e->resource, sizeof(e->resource), filename);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
