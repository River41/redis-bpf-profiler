#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

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
    bpf_printk("DEBUG: Entering processCommand\n");
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 tid = (u32)id;

    if (target_pid != 0 && pid != target_pid)
        return 0;

    u64 ts = bpf_ktime_get_ns();
    // Store the current timestamp in the map
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

    // Calculate latency: delta / 1000 is microseconds (us)
    bpf_printk("Redis processCommand latency: %llu ns\n", delta);

    // Delete after use to free up map space
    bpf_map_delete_elem(&start_times, &tid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";