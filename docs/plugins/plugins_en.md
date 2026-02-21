# Plugin Development Guide

`netxfw` supports dynamic loading of third-party plugins via the eBPF Tail Call mechanism. This allows developers to extend custom packet processing logic without modifying or recompiling the core firewall code.

## 1. Core Principle

After extracting basic packet information, the main XDP program of `netxfw` attempts to jump to a `BPF_MAP_TYPE_PROG_ARRAY` named `jmp_table`.
- **Plugin Index**: Plugins occupy indices `2` to `15` in the `jmp_table`.
- **Logic**: If a program exists at the index, the plugin logic is executed. After execution, the plugin should typically call `bpf_tail_call` to return to the main program's protocol handler, or directly return `XDP_PASS`/`XDP_DROP`.

## 2. Quick Start

### Prerequisites
- Install `clang` and `llvm`.
- Include `netxfw` BPF headers.

### Writing a Plugin
Create a `.c` file (e.g., `my_filter.bpf.c`):

```c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "include/plugin.h"

SEC("xdp")
int my_custom_filter(struct xdp_md *ctx) {
    // Your logic here
    // e.g., Drop specific packets
    
    // To continue to netxfw core logic
    return XDP_PASS; 
}

char _license[] SEC("license") = "GPL";
```

### Compiling
Use the `Makefile` provided by `netxfw`:
```bash
make plugins
```
The compiled object file will be located in `bpf/plugins/out/`.

## 3. Loading and Management

Use the `netxfw` CLI to manage plugins dynamically:

### Load Plugin
Load the compiled `.o` file to a specific jump table index (e.g., index 2):
```bash
sudo netxfw plugin load bpf/plugins/out/my_filter.o 2
```

### Remove Plugin
```bash
sudo netxfw plugin remove 2
```
