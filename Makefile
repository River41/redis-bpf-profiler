BPF_SRC = src/bpf/redis_monitor.bpf.c
USER_SRC = src/user/redis_monitor.c
OUTPUT = .
BPF_OBJ = $(OUTPUT)/redis_monitor.bpf.o
SKEL_H = $(OUTPUT)/redis_monitor.skel.h
TARGET = redis_monitor


CLANG = clang
BPFTOOL = bpftool
CFLAGS = -g -O2 -Wall -I. -I./src/user

all: $(TARGET)

# 1.
$(BPF_OBJ): $(BPF_SRC) vmlinux.h
	$(CLANG) $(CFLAGS) -target bpf -D__TARGET_ARCH_arm64 -c $(BPF_SRC) -o $@

# 2. Skeleton
$(SKEL_H): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $(BPF_OBJ) > $(SKEL_H)

# 3.
$(TARGET): $(USER_SRC) $(SKEL_H)
	$(CLANG) $(CFLAGS) $(USER_SRC) -lbpf -lelf -lz -o $@

clean:
	rm -f $(BPF_OBJ) $(SKEL_H) $(TARGET)

.PHONY: all clean