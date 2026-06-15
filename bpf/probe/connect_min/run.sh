#!/usr/bin/env bash
# A/B BPF-LSM socket_connect probe.
#
# CONTROL = mini.bpf.c        : address-only deny of 127.0.0.2 (known 0-leak).
# TEST    = mini_socktype.bpf.c: CONTROL + exactly the real connect hook's
#                                `sock->type` read and its fail-OPEN gate.
#
# If TEST leaks under the connect burst while CONTROL does not, the residual
# fail-open in jg_socket_connect.c is the sock->type read / fail-open gate.
set -e
cd "$(dirname "$0")"

echo "== generating vmlinux.h from this kernel =="
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

echo "== compiling =="
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I. -c mini.bpf.c -o mini.bpf.o
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I. -c mini_socktype.bpf.c -o mini_socktype.bpf.o
gcc loader.c -o loader -lbpf
gcc cli.c -o cli

N=2000
echo "== BASELINE (no LSM): expect leaked=$N =="
./cli "$N"

run_variant() {
  local obj="$1" label="$2"
  echo "== [$label] loading $obj =="
  sudo ./loader "$obj" &
  sleep 1
  echo "== [$label] WITH LSM (5 x $N): expect blocked=$N leaked=0 =="
  for _ in 1 2 3 4 5; do ./cli "$N"; done
  sudo pkill -x loader 2>/dev/null || true
  sleep 1
}

run_variant mini.bpf.o          "CONTROL  address-only"
run_variant mini_socktype.bpf.o "TEST     address + sock->type gate"
echo "== done =="
