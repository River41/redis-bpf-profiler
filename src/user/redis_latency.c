#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <fcntl.h>
#include <time.h>
#include <gelf.h>
#include <libelf.h>

#include "../redis_metadata.h"

typedef uint32_t u32;
#include "redis_latency.skel.h"

static volatile bool exiting = false;

static void sig_handler(int sig) {
    exiting = true;
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
    const struct event *e = data;
    struct tm *tm;
    char ts[32];
    time_t t;

    time(&t);
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    // 打印漂亮的表格行：时间、命令、参数个数、延迟(微秒)
    printf("%-10s %-12s %-8u %-10.2f\n", 
           ts, e->cmd, e->argc, e->latency_ns / 1000.0);

    return 0;
}

// libbpf error and info print callback
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    // Print warnings and errors in red
    if (level <= LIBBPF_WARN) {
        fprintf(stderr, "\033[1;31m[LIBBPF]\033[0m ");
    }
    return vfprintf(stderr, format, args);
}

/**
 * @brief Finds the offset of a symbol in an ELF file.
 *
 * This function opens an ELF file (executable or shared library) and
 * searches its symbol table for a given symbol name.
 *
 * @param path Path to the ELF file.
 * @param symbol_name The name of the symbol to find.
 * @return The offset of the symbol from the beginning of the file,
 *         or -1 if the symbol is not found or an error occurs.
 */
static long get_symbol_offset(const char *path, const char *symbol_name) {
    int fd;
    Elf *elf;
    GElf_Shdr shdr;
    Elf_Scn *scn = NULL;
    Elf_Data *data;
    long offset = -1;

    if (elf_version(EV_CURRENT) == EV_NONE) {
        fprintf(stderr, "ELF library initialization failed: %s\n", elf_errmsg(-1));
        return -1;
    }

    fd = open(path, O_RDONLY, 0);
    if (fd < 0) {
        fprintf(stderr, "Failed to open %s: %s\n", path, strerror(errno));
        return -1;
    }

    elf = elf_begin(fd, ELF_C_READ, NULL);
    if (!elf) {
        fprintf(stderr, "elf_begin() failed: %s\n", elf_errmsg(-1));
        close(fd);
        return -1;
    }

    // Iterate over sections to find the symbol table
    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        if (gelf_getshdr(scn, &shdr) != &shdr) {
            fprintf(stderr, "gelf_getshdr() failed: %s\n", elf_errmsg(-1));
            goto cleanup;
        }

        // We are interested in the symbol table (SHT_SYMTAB) or (SHT_DYNSYM)
        if (shdr.sh_type == SHT_SYMTAB || shdr.sh_type == SHT_DYNSYM) {
            data = elf_getdata(scn, NULL);
            int count = shdr.sh_size / shdr.sh_entsize;

            // Iterate over symbols in the table
            for (int i = 0; i < count; ++i) {
                GElf_Sym sym;
                gelf_getsym(data, i, &sym);
                const char *name = elf_strptr(elf, shdr.sh_link, sym.st_name);
                if (name && strcmp(name, symbol_name) == 0) {
                    offset = sym.st_value;
                    goto cleanup;
                }
            }
        }
    }

cleanup:
    elf_end(elf);
    close(fd);
    return offset;
}

int main(int argc, char **argv) {
    struct redis_latency_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;

    if (argc < 3) {
        fprintf(stderr, "Usage: %s <REDIS_PATH> <REDIS_PID>\n", argv[0]);
        return 1;
    }

    const char *redis_path = argv[1];
    u32 redis_pid = strtoul(argv[2], NULL, 10);
    long func_offset;

    // Dynamically find the offset of the 'processCommand' function
    func_offset = get_symbol_offset(redis_path, "processCommand");
    if (func_offset < 0) {
        fprintf(stderr, "Failed to find symbol 'processCommand' in %s\n", redis_path);
        return 1;
    }
    printf("Found 'processCommand' at offset 0x%lx in %s\n", func_offset, redis_path);

    // Set up libbpf logging and signal handler
    libbpf_set_print(libbpf_print_fn);
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = redis_latency_bpf__open();
    if (!skel) return 1;

    skel->rodata->target_pid = redis_pid;

    err = redis_latency_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        goto cleanup;
    }

    // Key point: Manually attach the Uprobe because it requires specifying the binary path and function name
    skel->links.process_command_entry = bpf_program__attach_uprobe(
        skel->progs.process_command_entry,
        false, /* not a uretprobe */
        redis_pid,
        redis_path,
        func_offset      /* DYNAMIC offset from symbol start */
    );
    if (!skel->links.process_command_entry) {
        // libbpf_get_error returns the last error code. For attach failures, it's often in errno.
        err = -libbpf_get_error(skel->links.process_command_entry);
        fprintf(stderr, "Failed to attach uprobe to 'processCommand': %s\n", strerror(-err));
        goto cleanup;
    }

    // Attach the Uretprobe
    skel->links.process_command_exit = bpf_program__attach_uprobe(
        skel->progs.process_command_exit,
        true, /* is a uretprobe */
        redis_pid,
        redis_path,
        func_offset /* The uretprobe attaches to the same offset */
    );
    if (!skel->links.process_command_exit) {
        err = -libbpf_get_error(skel->links.process_command_exit);
        fprintf(stderr, "Failed to attach uretprobe to 'processCommand': %s\n", strerror(-err));
        goto cleanup;
    }

    printf("Successfully attached! Watching for 'processCommand' in %s (PID: %u).\n", redis_path, redis_pid);
    printf("Check kernel trace pipe for output: sudo cat /sys/kernel/debug/tracing/trace_pipe\n");
    printf("Press Ctrl-C to exit.\n");

    // 1. 初始化 Ring Buffer 监听器
    // "rb" 对应我们在 .bpf.c 里定义的 SEC(".maps") 中的那个 rb
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("\n%-10s %-12s %-8s %-10s\n", "TIME", "COMMAND", "ARGC", "LATENCY(us)");
    printf("----------------------------------------------------------\n");

    // 2. 进入情报轮询循环
    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* 100毫秒超时一次，方便检查退出信号 */);
        if (err == -EINTR) continue;
        if (err < 0) {
            printf("Error polling ring buffer: %d\n", err);
            break;
        }
    }

cleanup:
    redis_latency_bpf__destroy(skel);
    return -err;
}