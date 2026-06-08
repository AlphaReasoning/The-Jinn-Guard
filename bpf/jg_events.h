/* SPDX-License-Identifier: GPL-2.0
 *
 * jg_events.h — Shared event structure written by all Jinn Guard eBPF programs
 * into the EVENTS RingBuf map.  Must match RawEbpfEvent in ebpf_monitor.rs.
 *
 * Layout (packed):
 *   u8  probe_id        — 0=execve, 1=openat, 2=connect, 3=cap_capable
 *   u32 pid             — PID of the triggering task
 *   u8  resource[128]   — NUL-terminated path / address string
 *   u8  denied          — non-zero if the kernel itself denied the call
 */

#pragma once

/*
 * CO-RE BPF programs include vmlinux.h before this header.  Keep this header
 * free of system kernel includes such as <linux/types.h>; the __u* typedefs
 * below come from vmlinux.h so they match the target kernel BTF.
 */

/* Probe identifier constants */
#define JG_PROBE_EXECVE   0
#define JG_PROBE_OPENAT   1
#define JG_PROBE_CONNECT  2
#define JG_PROBE_CAPABLE  3

#define JG_RESOURCE_LEN   128

struct jg_event {
    __u8  probe_id;
    __u32 pid;
    __u8  resource[JG_RESOURCE_LEN];
    __u8  denied;
} __attribute__((packed));
