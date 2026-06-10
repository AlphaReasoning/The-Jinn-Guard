/* SPDX-License-Identifier: GPL-2.0
 *
 * bpf/common/maps.h - Shared BPF map declarations.
 */
#pragma once

/*
 * The LSM hooks are built and loaded as independent ELF objects. Pinning this
 * map by name lets the loader reuse one kernel ring buffer across all objects
 * instead of creating one fragmented "requests" ring buffer per hook.
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} requests SEC(".maps");
