# XDP Plugin Development Guide

## Overview

netxfw supports dynamically loading third-party XDP plugins through the eBPF Tail Call mechanism. This allows developers to extend custom packet processing logic without modifying or recompiling the core firewall code.

## Core Principles

After extracting basic packet information, netxfw's main XDP program attempts to jump to a `BPF_MAP_TYPE_PROG_ARRAY` named `jmp_table`.

- **Plugin Index**: Plugins occupy index positions `2` to `15` in `jmp_table`
- **Core Logic**: If a program exists at the index position, execute the plugin logic; after the plugin finishes execution, it should typically call `bpf_tail_call` to return to the main program's protocol handler, or directly return `XDP_PASS`/`XDP_DROP`

## Environment Requirements

- Linux kernel 4.18+ (supports eBPF/XDP)
- Clang/LLVM toolchain
- libbpf-dev or bpftool

## Quick Start

### 1. Write Plugin

Create a `.c` file (e.g., `my_filter.bpf.c`):

```c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

// Import netxfw helper functions and structure definitions
#include "include/protocol.h"
#include "include/maps.bpf.h"
#include "include/helpers.bpf.h"

SEC("xdp")
int my_custom_filter(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;  // Packet length insufficient, pass to subsequent processing

    // Process only IPv4 packets
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = data + sizeof(*eth);
        if (data + sizeof(*eth) + sizeof(*ip) > data_end)
            return XDP_PASS;

        // Example: Block traffic from specific source IP
        __u32 blocked_ip = 0x01010101; // 1.1.1.1
        if (ip->saddr == blocked_ip) {
            return XDP_DROP;  // Block traffic from this IP
        }
        
        // Example: Special handling for specific ports
        if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (void *)ip + sizeof(*ip);
            if ((void *)tcp + sizeof(*tcp) <= data_end) {
                __u16 dest_port = bpf_ntohs(tcp->dest);
                
                // If destination port is 8080, execute special logic
                if (dest_port == 8080) {
                    // Add custom processing logic here
                    // Example: Record statistics to custom map
                    // bpf_printk("Custom processing for port 8080\n");
                }
            }
        }
    }

    // Let packet continue to netxfw core logic
    bpf_tail_call(ctx, &jmp_table, PROG_IDX_PLUGIN_END);
    
    // If tail call fails, continue processing
    return XDP_PASS;
}

// Define license (required)
char _license[] SEC("license") = "GPL";
```

### 2. Compile Plugin

Use netxfw's Makefile to compile the plugin:

```bash
make plugins
```

Compilation output will be located in the `bpf/plugins/out/` directory.

### 3. Load Plugin

Use netxfw command-line tool to dynamically manage plugins:

#### Load Plugin
Load the compiled `.o` file to a specific jump table index (e.g., index 2):

```bash
sudo ./netxfw plugin load bpf/plugins/out/my_filter.bpf.o 2
```

#### Remove Plugin
Remove plugin from specific index:

```bash
sudo ./netxfw plugin remove 2
```

## Plugin Development Best Practices

### 1. Performance Optimization
- Minimize loops and complex calculations within plugins
- Use pre-allocated BPF maps to avoid dynamic memory allocation
- Consider using Per-CPU maps to reduce lock contention

### 2. Security Considerations
- Always validate packet length to prevent out-of-bounds access
- Avoid infinite loops, ensure program always terminates in finite time
- Use `bpf_skb_load_bytes()` to safely access packet content

### 3. Error Handling
- Return `XDP_PASS` when packet format is invalid, let subsequent processing decide
- Use `bpf_printk()` for debugging information (requires root permission to view)

### 4. Collaboration with Main Program
- Use BPF maps to share state with main program
- Follow main program's data structure definitions
- Call `bpf_tail_call()` at appropriate times to return to main flow

## Advanced Features

### 1. Custom Statistics

Plugins can use their own BPF maps to record statistics:

```c
// Define map in plugin
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} my_stats SEC(".maps");

SEC("xdp")
int my_advanced_filter(struct xdp_md *ctx) {
    // ... processing logic ...
    
    // Update statistics
    __u32 key = 0;
    __u64 *count = bpf_map_lookup_elem(&my_stats, &key);
    if (count) (*count)++;
    
    return XDP_PASS;
}
```

### 2. External Configuration

Plugins can receive configuration parameters from userspace:

```c
// Configuration map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 10);
    __type(key, __u32);
    __type(value, __u32);
} plugin_config SEC(".maps");

SEC("xdp")
int my_configurable_filter(struct xdp_md *ctx) {
    __u32 config_key = 0;
    __u32 *config_value = bpf_map_lookup_elem(&plugin_config, &config_key);
    
    if (config_value && *config_value == 1) {
        // Execute specific logic based on configuration
        return XDP_PASS;
    }
    
    return XDP_PASS;
}
```

## Debugging Tips

### 1. Log Output
Use `bpf_printk()` to output debugging information (requires root permission to view):

```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

### 2. Validate Plugin
Use bpftool to check loaded plugins:

```bash
sudo bpftool prog show
sudo bpftool map show
```

## Limitations and Notes

1. **Program Complexity**: XDP programs are subject to verifier restrictions and cannot be overly complex
2. **Memory Access**: Strictly adhere to packet boundary checks
3. **Resource Limits**: BPF map size and program instruction count are limited
4. **Compatibility**: BPF features may vary slightly between different kernel versions

## Example Plugins

The `bpf/plugins/` directory in the project contains multiple example plugins for development reference.

## Troubleshooting

- **Verifier Error**: Check packet boundary access and loop complexity
- **Load Failure**: Ensure plugin index is within valid range (2-15)
- **Performance Degradation**: Check plugin logic complexity and map operation frequency