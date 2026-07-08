## SPDX-License-Identifier: GPL-2.0
#
# bpf/Makefile — Build system for Jinn Guard eBPF programs

CLANG     ?= clang
INSTALL   ?= install
BPFTOOL   ?= bpftool
OUT       ?= .

# Derive the kernel-style arch name from the build machine so `make` works on
# x86_64 and aarch64 without a manual override. clang/kernel expect the short
# names (x86, arm64), not the uname -m values (x86_64, aarch64). Override with
# `make ARCH=...` for cross-compiles. Defaults to x86 for unknown machines.
UNAME_M      := $(shell uname -m)
ARCH_x86_64  := x86
ARCH_aarch64 := arm64
ARCH      ?= $(or $(ARCH_$(UNAME_M)),x86)

# Kernel headers
KDIR      ?= /usr/src/linux-headers-$(shell uname -r)
KINCLUDE   = -I$(KDIR)/arch/$(ARCH)/include \
             -I$(KDIR)/arch/$(ARCH)/include/generated \
             -I$(KDIR)/include \
             -I$(KDIR)/arch/$(ARCH)/include/uapi \
             -I$(KDIR)/include/uapi

LIBBPF_INCLUDE ?= /usr/include

BPF_CFLAGS  = -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) -I$(LIBBPF_INCLUDE) -I. -I$(OUT) $(KINCLUDE)

TRACEPOINT_SRCS = jg_execve.bpf.c \
                  jg_openat.bpf.c

# Optional legacy telemetry. Not required for enterprise LSM enforcement tests,
# which load only $(LSM_TARGET) through AyaLsmMonitor.
LEGACY_TELEMETRY_SRCS = jg_cap_capable.bpf.c

LSM_SRCS = lsm/jg_socket_connect.c \
           lsm/jg_socket_sendmsg.c \
           lsm/jg_bprm_check_security.c \
           lsm/jg_inode_create.c \
           lsm/jg_inode_unlink.c \
           lsm/jg_capable.c \
           lsm/jg_sb_mount.c \
           lsm/jg_sb_pivotroot.c \
           lsm/jg_move_mount.c \
           lsm/jg_file_open.c

TRACEPOINT_OBJS = $(TRACEPOINT_SRCS:.bpf.c=.bpf.o)
LSM_OBJS = $(LSM_SRCS:.c=.o)
LEGACY_TELEMETRY_OBJS = $(LEGACY_TELEMETRY_SRCS:.bpf.c=.bpf.o)
INSTALL_DIR = /usr/lib/jinnguard

.PHONY: all clean install check-tools legacy-telemetry regen-vmlinux

all: check-tools $(OUT)/vmlinux.h $(TRACEPOINT_OBJS) $(LSM_OBJS)

$(OUT)/vmlinux.h:
	@mkdir -p $(OUT)
	@echo "  GEN     $@"
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

# The committed bpf/vmlinux.h is x86-generated (vendored so CI can compile the
# LSM objects without BTF on the runner). CO-RE relocates field offsets at load,
# but on a foreign arch (aarch64) or after a kernel bump, regenerate it from the
# local BTF: `make -C bpf regen-vmlinux`.
regen-vmlinux: check-tools
	@echo "  REGEN   $(OUT)/vmlinux.h from local BTF ($(UNAME_M))"
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(OUT)/vmlinux.h

check-tools:
	@command -v $(CLANG) >/dev/null 2>&1 || \
		{ echo "ERROR: clang not found. Install with: apt install clang"; exit 1; }
	@command -v $(BPFTOOL) >/dev/null 2>&1 || \
		{ echo "ERROR: bpftool not found. Install with: apt install linux-tools-common"; exit 1; }
	@test -d $(LIBBPF_INCLUDE)/bpf || \
		{ echo "ERROR: libbpf headers missing. Install with: apt install libbpf-dev"; exit 1; }

# Build independent ELF BPF objects. Do not llvm-link these outputs:
# clang -target bpf -c emits ELF objects, and each source owns its maps/LICENSE.
%.bpf.o: %.bpf.c jg_events.h $(OUT)/vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

lsm/%.o: lsm/%.c lsm/jg_common.h common/maps.h common/governed_floor.h $(OUT)/vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

legacy-telemetry: check-tools $(OUT)/vmlinux.h $(LEGACY_TELEMETRY_OBJS)
	@echo "  LEGACY  capability telemetry object built separately"

install: all
	$(INSTALL) -d $(INSTALL_DIR)
	$(INSTALL) -d $(INSTALL_DIR)/lsm
	$(INSTALL) -m 0644 $(TRACEPOINT_OBJS) $(INSTALL_DIR)/
	$(INSTALL) -m 0644 $(LSM_OBJS) $(INSTALL_DIR)/lsm/
	@echo "  INSTALL tracepoint objects -> $(INSTALL_DIR)"
	@echo "  INSTALL LSM objects -> $(INSTALL_DIR)/lsm"

clean:
	rm -f $(TRACEPOINT_OBJS) $(LSM_OBJS) $(LEGACY_TELEMETRY_OBJS) $(OUT)/vmlinux.h
	@echo "  CLEAN"
