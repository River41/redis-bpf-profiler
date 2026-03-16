#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

// This is a global variable that can be configured from the user-space application
// before the BPF program is loaded. It allows filtering events for a specific PID.
// A value of 0 means no filtering (trace all processes).
volatile const u32 target_pid = 0;

// This BPF program attaches to the sys_enter_write tracepoint.
// It will be triggered every time any process on the system enters the write() syscall.
SEC("tracepoint/syscalls/sys_enter_write")
int handle_tp_write(struct trace_event_raw_sys_enter *ctx)
{
	// Mark ctx as unused to avoid compiler warnings.
	(void)ctx;

	// Get the process ID (PID) and thread ID (TID) of the current task.
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32; // The upper 32 bits are the PID.

	// If a target_pid is set, filter out events from other processes.
    if (target_pid != 0 && pid != target_pid) {
        return 0; // Exit immediately if it's not the target PID.
	}

	// If we are tracing this PID, print a message to the kernel trace pipe.
	// You can view this with: sudo cat /sys/kernel/debug/tracing/trace_pipe
    bpf_printk("Target process (PID %d) is writing!\n", pid);

    return 0;
}

// All BPF programs must have a license.
char LICENSE[] SEC("license") = "GPL";