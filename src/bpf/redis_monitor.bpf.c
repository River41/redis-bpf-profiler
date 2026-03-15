#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

/* 定义一个全局变量，用户态可以直接修改它 */
/* Define a global variable that can be modified directly from user space */
volatile const u32 target_pid = 0;

SEC("tracepoint/syscalls/sys_enter_write")
int handle_tp_write(struct trace_event_raw_sys_enter *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;

    /* If it's not the PID we're looking for, just let it pass without any processing */
    if (target_pid != 0 && pid != target_pid)
        return 0;

    bpf_printk("Target Redis (PID %d) is writing!\n", pid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";