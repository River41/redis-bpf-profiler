#include <unistd.h>
#include <bpf/libbpf.h>
typedef uint32_t u32;
#include "redis_monitor.skel.h"

// 错误处理回调
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    // 如果是警告级别，打印红色的 [ERROR] 标签
    if (level == LIBBPF_WARN) {
        // \033[1;31m 是加粗红色的代码，\033[0m 是重置颜色的代码
        fprintf(stderr, "\033[1;31m[ERROR]\033[0m ");
    } else if (level == LIBBPF_INFO) {
        // 也可以给普通信息加个绿色的 [INFO]
        fprintf(stderr, "\033[1;32m[INFO]\033[0m  ");
    }

    // 转发原始的日志信息
    return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
    struct redis_monitor_bpf *skel;
    int err;
    u32 redis_pid = 0;

    // 简单起见，我们从命令行参数读 PID：./redis_monitor 1234
    if (argc > 1) {
        redis_pid = strtoul(argv[1], NULL, 10);
    }

    /* 设置 libbpf 的错误和信息打印回调 */
    libbpf_set_print(libbpf_print_fn);

    skel = redis_monitor_bpf__open(); // 注意：这里先 open，不直接 load
    if (!skel) return 1;

    /* 在 load 之前，修改内核态的全局变量 */
    if (redis_pid > 0) {
        skel->rodata->target_pid = redis_pid;
        printf("Filtering for Redis PID: %u\n", redis_pid);
    }

    err = redis_monitor_bpf__load(skel); // 然后再真正加载进内核

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