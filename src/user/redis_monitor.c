#include <unistd.h>
#include <bpf/libbpf.h>
typedef uint32_t u32;
#include "redis_monitor.skel.h"

// Error handling callback
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    // If the level is WARN, print a red [ERROR] tag
    if (level == LIBBPF_WARN) {
        // \033[1;31m is the code for bold red, \033[0m resets the color
        fprintf(stderr, "\033[1;31m[ERROR]\033[0m ");
    } else if (level == LIBBPF_INFO) {
        // We can also add a green [INFO] for normal messages
        fprintf(stderr, "\033[1;32m[INFO]\033[0m  ");
    }

    // Forward the original log message
    return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
    struct redis_monitor_bpf *skel;
    int err;
    u32 redis_pid = 0;

    // For simplicity, we read the PID from command line arguments: ./redis_monitor 1234
    if (argc > 1) {
        redis_pid = strtoul(argv[1], NULL, 10);
    }

    /* Set the libbpf error and info print callback */
    libbpf_set_print(libbpf_print_fn);

    skel = redis_monitor_bpf__open(); // Note: open first, don't load directly
    if (!skel) return 1;

    /* Before loading, modify the kernel-space global variable */
    if (redis_pid > 0) {
        skel->rodata->target_pid = redis_pid;
        printf("Filtering for Redis PID: %u\n", redis_pid);
    }

    err = redis_monitor_bpf__load(skel); // Then, actually load it into the kernel

    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        goto cleanup;
    }

    err = redis_monitor_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    printf("Successfully started! Check 'sudo cat /sys/kernel/debug/tracing/trace_pipe' for output.\n");
    printf("Press Ctrl+C to stop.\n");

    // 3. Continue until Ctrl+C
    for (;;) {
        pause();
    }

cleanup:
    redis_monitor_bpf__destroy(skel);
    return -err;
}