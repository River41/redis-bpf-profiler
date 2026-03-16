#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "../redis_metadata.h"

#define CLIENT_ARGC_OFFSET 88
#define CLIENT_ARGV_OFFSET 96
#define ROBJ_PTR_OFFSET 8

// Forward declarations for structs we are probing from userspace.
// These definitions do not need to be complete, as we only need the type.
struct client;
struct redisObject; // In Redis, this is the `robj` type

struct session {
    // Stores metadata about a command at its entry point.
    unsigned long long start_ts;
    char cmd[16];
    int argc;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);              // Key: Thread ID (TID)
    __type(value, struct session); // Value: Session metadata
} start_sessions SEC(".maps");

// Ring buffer to send events from kernel to user space.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256KB buffer
} rb SEC(".maps");

// Optional PID filter. Set from user space to trace a specific process.
volatile const u32 target_pid = 0;

// This uprobe is triggered at the entry of the `processCommand` function in Redis.
SEC("uprobe")
int BPF_UPROBE(process_command_entry)
{
    // The first argument to processCommand is `struct client *c`.
    u64 client_ptr_val = PT_REGS_PARM1(ctx);
    if (!client_ptr_val)
        return 0;

    // Get the Process ID (PID) and Thread ID (TID).
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 tid = (u32)id;

    // Filter by PID if one was provided from userspace
    if (target_pid != 0 && pid != target_pid)
        return 0;

    // The following chain of reads traverses Redis's internal structures to get
    // the command name. It is equivalent to C-like access: `(char *)c->argv[0]->ptr`

    // 1. Read `c->argv` pointer.
    struct redisObject **argv_ptr;
    if (bpf_probe_read_user(&argv_ptr, sizeof(argv_ptr), (void *)(client_ptr_val + CLIENT_ARGV_OFFSET)) != 0) {
        bpf_printk("BPF: failed to read client->argv at offset %d\n", CLIENT_ARGV_OFFSET);
        return 0;
    }

    // 2. Read `c->argv[0]` pointer, which points to an `robj`.
    struct redisObject *first_arg_robj_ptr;
    if (bpf_probe_read_user(&first_arg_robj_ptr, sizeof(first_arg_robj_ptr), argv_ptr) != 0) {
        bpf_printk("BPF: failed to read client->argv[0]\n");
        return 0;
    }

    // 3. Read `ptr` from the `robj` to get the command string pointer.
    void *string_ptr;
    if (bpf_probe_read_user(&string_ptr, sizeof(string_ptr), (void *)((u64)first_arg_robj_ptr + ROBJ_PTR_OFFSET)) != 0) {
        bpf_printk("BPF: failed to read robj->ptr at offset %d\n", ROBJ_PTR_OFFSET);
        return 0;
    }

    // 4. Read the actual command name string.
    char cmdname[16];
    __builtin_memset(cmdname, 0, sizeof(cmdname));
    bpf_probe_read_user_str(&cmdname, sizeof(cmdname), string_ptr);

    // 5. Read `c->argc` for additional context.
    int current_argc;
    bpf_probe_read_user(&current_argc, sizeof(current_argc), (void *)(client_ptr_val + CLIENT_ARGC_OFFSET));

    // For debugging: print the captured command to the kernel trace pipe.
    bpf_printk("Redis command: %s (argc: %d)\n", cmdname, current_argc);

    // Store the session information in a map, keyed by the thread ID.
    // This allows the return probe to look up the start time and command details.
    struct session s = {};
    s.start_ts = bpf_ktime_get_ns();
    s.argc = current_argc;
    bpf_probe_read_user_str(&s.cmd, sizeof(s.cmd), string_ptr);

    bpf_map_update_elem(&start_sessions, &tid, &s, BPF_ANY);
    return 0;
}

// This uretprobe is triggered at the exit of the `processCommand` function.
SEC("uretprobe")
int BPF_URETPROBE(process_command_exit) {
    u32 tid = (u32)bpf_get_current_pid_tgid();

    // Look up the session info stored by the entry probe.
    struct session *s = bpf_map_lookup_elem(&start_sessions, &tid);
    if (!s) return 0;

    // Calculate the command execution time.
    unsigned long long delta = bpf_ktime_get_ns() - s->start_ts;

    // Reserve space on the ring buffer for the event.
    struct event *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (e) {
        // Populate the event with command details and latency.
        __builtin_memcpy(e->cmd, s->cmd, sizeof(e->cmd));
        e->argc = s->argc;
        e->latency_ns = delta;
        // Submit the event to the ring buffer for user-space to consume.
        bpf_ringbuf_submit(e, 0);
    }

    // Clean up the session from the map.
    bpf_map_delete_elem(&start_sessions, &tid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";