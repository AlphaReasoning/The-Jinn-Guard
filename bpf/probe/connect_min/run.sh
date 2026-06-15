#!/usr/bin/env bash
# Minimal BPF-LSM socket_connect enforcement probe.
# Settles kernel-vs-Jinn-Guard attribution for the TCP-connect fail-open:
#   * blocked=N, leaked=0 every run  -> kernel honors socket_connect -EPERM;
#                                       the fail-open is in Jinn Guard's code.
#   * leaked>0                       -> a real kernel socket_connect quirk,
#                                       reproducible with these ~25 lines.
set -e
cd "$(dirname "$0")"

echo "== generating vmlinux.h from this kernel =="
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

echo "== compiling =="
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I. -c mini.bpf.c -o mini.bpf.o
gcc loader.c -o loader -lbpf
gcc cli.c -o cli

echo "== BASELINE (no LSM): expect leaked=500 =="
./cli 500

echo "== loading minimal deny-127.0.0.2 LSM =="
sudo ./loader &
sleep 1

echo "== WITH LSM (3 runs): expect blocked=500 leaked=0 =="
./cli 500
./cli 500
./cli 500

echo "== detaching =="
sudo pkill -x loader 2>/dev/null || true
echo "== done =="
