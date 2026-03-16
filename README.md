# Redis-BPF-Profiler

A non-invasive, high-performance Redis profiling tool powered by **eBPF**. It monitors command latency, types, and argument counts by attaching **Uprobes** to the Redis internal function `processCommand`.

## Getting Started

### Prerequisites
* Linux Kernel >= 5.8
* Dependencies: `libbpf`, `libelf`, `clang`, `llvm`

### Build
```bash
make
```

### Run
```bash
# Get Redis path and PID
REDIS_PATH=$(realpath $(which redis-server))
REDIS_PID=$(pgrep redis-server)

# Start Profiling
sudo ./redis_latency $REDIS_PATH $REDIS_PID
```

## Output Example

```text
TIME       COMMAND      ARGC     LATENCY(us)
23:45:01   SET          3        42.15
23:45:02   LPUSH        6        115.80
23:45:05   KEYS         2        5240.12   <-- O(N) complexity detected
```

## Key Features

* **Non-Invasive**: No code changes or restarts required for the target Redis instance.
* **Protocol-Aware**: Deeply inspects Redis memory to extract command names (e.g., `SET`, `GET`, `KEYS`) and `argc`.
* **Nanosecond Precision**: Captures exact execution time within the Redis event loop.
* **Real-Time Streaming**: Uses **BPF Ring Buffer** for efficient, low-overhead data transfer to userspace.
* **Stripped Binary Support**: Built-in ELF parser to resolve offsets from the dynamic symbol table (`SHT_DYNSYM`).

## Architecture

* **Kernel (BPF)**: Intercepts `processCommand` entry/exit. Implements **pointer chasing** from `struct client` to `robj` to resolve command strings.
* **Userspace (C)**: Manages BPF lifecycle, handles symbol resolution, and renders real-time performance data.
* **Shared**: Unified data structures in `src/redis_metadata.h` for seamless communication.

## Technical Implementation: Pointer Chasing

To identify commands even when `c->cmd` is uninitialized at function entry, this tool resolves the command name via the following memory path:

$$\text{client} \xrightarrow{+96} \text{argv array} \xrightarrow{[0]} \text{robj} \xrightarrow{+8} \text{ptr} \rightarrow \text{"Command Name"}$$

## Author
**Zhiyuan (River) Lu** *Columbia University*