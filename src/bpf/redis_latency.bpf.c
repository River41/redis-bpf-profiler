#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>


#define CLIENT_ARGC_OFFSET 88
#define CLIENT_ARGV_OFFSET 96
#define ROBJ_PTR_OFFSET 8

// Forward declarations for structs we are probing from userspace.
// These definitions do not need to be complete, as we only need the type.
struct redisCommand;
struct client;
struct redisObject; // In Redis, this is the `robj` type

// Define a Hash Map to store the entry timestamp for each thread
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024); // Sufficient for single-threaded Redis
    __type(key, u32);   // Key is Thread ID (TID)
    __type(value, u64); // Value is the entry timestamp (nanoseconds)
} start_times SEC(".maps");

// Optional PID filter passed from user space
volatile const u32 target_pid = 0;

// 1. Probe at function entry (Uprobe)
SEC("uprobe")
int BPF_UPROBE(process_command_entry)
{
    // The first argument to processCommand is `struct client *c`.
    u64 client_ptr_val = PT_REGS_PARM1(ctx);
    if (!client_ptr_val)
        return 0;

    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 tid = (u32)id;

    // Filter by PID if one was provided from userspace
    if (target_pid != 0 && pid != target_pid)
        return 0;

    // This chain of reads traverses Redis's internal structures to get the command name.
    // It's equivalent to: `(char *)c->argv[0]->ptr`

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
    int argc;
    bpf_probe_read_user(&argc, sizeof(argc), (void *)(client_ptr_val + CLIENT_ARGC_OFFSET));

    // 6. Print the result.
    bpf_printk("Redis command: %s (argc: %d)\n", cmdname, argc);

    // Store the entry timestamp in the map
    u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start_times, &tid, &ts, BPF_ANY);
    return 0;
}

// 2. Probe at function exit (Uretprobe)
SEC("uretprobe")
int BPF_URETPROBE(process_command_exit)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 tid = (u32)id;

    // Look up the corresponding entry time from the map
    u64 *start_ts = bpf_map_lookup_elem(&start_times, &tid);
    if (!start_ts)
        return 0;

    u64 end_ts = bpf_ktime_get_ns();
    u64 delta = end_ts - *start_ts;

    // Print latency. The indentation makes it easy to associate with the command.
    bpf_printk("  -> latency: %llu ns\n", delta);

    // Delete after use to free up map space
    bpf_map_delete_elem(&start_times, &tid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";