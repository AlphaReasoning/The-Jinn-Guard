## SPDX-License-Identifier: GPL-2.0
#
# bpf/Makefile — Build system for Jinn Guard eBPF programs

CLANG     ?= clang
INSTALL   ?= install
BPFTOOL   ?= bpftool
ARCH      ?= x86
OUT       ?= .

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
           lsm/jg_inode_unlink.c

TRACEPOINT_OBJS = $(TRACEPOINT_SRCS:.bpf.c=.bpf.o)
LSM_OBJS = $(LSM_SRCS:.c=.o)
LEGACY_TELEMETRY_OBJS = $(LEGACY_TELEMETRY_SRCS:.bpf.c=.bpf.o)
INSTALL_DIR = /usr/lib/jinnguard

.PHONY: all clean install check-tools legacy-telemetry

all: check-tools $(OUT)/vmlinux.h $(TRACEPOINT_OBJS) $(LSM_OBJS)

$(OUT)/vmlinux.h:
	@mkdir -p $(OUT)
	@echo "  GEN     $@"
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

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

lsm/%.o: lsm/%.c lsm/jg_common.h $(OUT)/vmlinux.h
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
