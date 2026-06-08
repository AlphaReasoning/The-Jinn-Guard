// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "jg_events.h"

extern struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);
} EVENTS SEC(".maps");

SEC("kprobe/cap_capable")
int BPF_KPROBE(jg_cap_capable, const struct cred *cred, struct user_namespace *ns, int cap, int cap_opt)
{
    struct jg_event *e;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    e = bpf_ringbuf_reserve(&EVENTS, sizeof(*e), 0);
    if (!e)
        return 0;

    e->probe_id = JG_PROBE_CAPABLE;
    e->pid      = pid;
    e->denied   = 0;

    char fmt[] = "cap=%d";
    bpf_snprintf(e->resource, sizeof(e->resource), fmt, cap);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
