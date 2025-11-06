# Makefile
CLANG = clang
BPF_CFLAGS = -g -O2 -target bpf -D__TARGET_ARCH_arm64
VMLINUX_H = ./pkg/ebpf/vmlinux.h

# Make 'build-ebpf' the default target
.PHONY: all
all: build-ebpf

# --- Build eBPF Probe ---
build-ebpf: pkg/ebpf/probe.o

pkg/ebpf/probe.o: pkg/ebpf/probe.c $(VMLINUX_H)
	@echo "  CLANG   $(CURDIR)/pkg/ebpf/probe.c"
	@$(CLANG) $(BPF_CFLAGS) \
		-I $(dir $<) \
		-c $< -o $@

# --- Helpers ---
.PHONY: clean
clean:
	@echo "  CLEAN"
	@rm -f pkg/ebpf/probe.o