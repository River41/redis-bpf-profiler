# Common variables
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
CC = clang
BPFTOOL = bpftool

# Common flags
CFLAGS = -g -O2 -Wall
LDFLAGS = -lbpf -lelf -lz
BPF_CFLAGS = -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)

# Include paths for user-space and BPF sources
# We add '.' to the path so that source files can find generated headers
# and vmlinux.h in the project root.
INCLUDES = -I.

# List of all executables to build
TARGETS = redis_monitor redis_latency

# Default target: build all executables
.PHONY: all
all: $(TARGETS)

# Rule to generate vmlinux.h for CO-RE. This is a file target, so 'make'
# will automatically run this rule if vmlinux.h is missing.
vmlinux.h:
	@echo "  GEN-CORE  $@"
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

# Generic rule for building user-space applications.
# It depends on the corresponding C source and the generated skeleton header.
# e.g., redis_monitor: src/user/redis_monitor.c redis_monitor.skel.h
$(TARGETS): %: src/user/%.c %.skel.h
	$(CC) $(CFLAGS) $(INCLUDES) $< -o $@ $(LDFLAGS)

# Generic rule for generating skeleton headers from BPF object files.
%.skel.h: %.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

# Generic rule for compiling BPF C code into BPF object files.
# It depends on the BPF source file and vmlinux.h for CO-RE.
%.bpf.o: src/bpf/%.bpf.c vmlinux.h
	$(CC) $(BPF_CFLAGS) $(INCLUDES) -c $< -o $@

# Phony target to clean up all generated files
.PHONY: clean
clean:
	rm -f $(TARGETS) *.bpf.o *.skel.h vmlinux.h