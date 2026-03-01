# XDP插件开发指南

## 概述

netxfw 支持通过 eBPF Tail Call 机制动态加载第三方 XDP 插件。这允许开发者在不修改或重新编译核心防火墙代码的情况下，扩展自定义的数据包处理逻辑。

## 核心原理

netxfw 的主 XDP 程序在提取完数据包基本信息后，会尝试跳转到一个名为 `jmp_table` 的 `BPF_MAP_TYPE_PROG_ARRAY`。

- **插件索引**: 插件占据 `jmp_table` 的 `2` 到 `15` 号索引位
- **核心逻辑**: 如果索引位有程序，则执行插件逻辑；插件执行完毕后，通常应调用 `bpf_tail_call` 返回主程序的协议处理器，或直接返回 `XDP_PASS`/`XDP_DROP`

## 环境要求

- Linux 内核 4.18+ (支持 eBPF/XDP)
- Clang/LLVM 工具链
- libbpf-dev 或 bpftool

## 快速开始

### 1. 编写插件

创建一个 `.c` 文件（例如 `my_filter.bpf.c`）：

```c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

// 导入 netxfw 的辅助函数和结构定义
#include "include/protocol.h"
#include "include/maps.bpf.h"
#include "include/helpers.bpf.h"

SEC("xdp")
int my_custom_filter(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;  // 数据包长度不足，传递给后续处理

    // 仅处理 IPv4 数据包
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = data + sizeof(*eth);
        if (data + sizeof(*eth) + sizeof(*ip) > data_end)
            return XDP_PASS;

        // 示例：阻止特定源 IP 的流量
        __u32 blocked_ip = 0x01010101; // 1.1.1.1
        if (ip->saddr == blocked_ip) {
            return XDP_DROP;  // 阻止该 IP 的流量
        }
        
        // 示例：对特定端口进行特殊处理
        if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (void *)ip + sizeof(*ip);
            if ((void *)tcp + sizeof(*tcp) <= data_end) {
                __u16 dest_port = bpf_ntohs(tcp->dest);
                
                // 如果目标端口是 8080，执行特殊逻辑
                if (dest_port == 8080) {
                    // 在这里添加自定义处理逻辑
                    // 例如：记录统计数据到自定义映射
                    // bpf_printk("Custom processing for port 8080\n");
                }
            }
        }
    }

    // 让数据包继续流向 netxfw 核心逻辑
    bpf_tail_call(ctx, &jmp_table, PROG_IDX_PLUGIN_END);
    
    // 如果尾调用失败，继续处理
    return XDP_PASS;
}

// 定义许可证（必需）
char _license[] SEC("license") = "GPL";
```

### 2. 编译插件

使用 `netxfw` 提供的 Makefile 编译插件：

```bash
make plugins
```

编译产物将位于 `bpf/plugins/out/` 目录下。

### 3. 加载插件

使用 `netxfw` 命令行工具动态管理插件：

#### 加载插件
将编译好的 `.o` 文件加载到指定的跳转表索引（例如索引 2）：

```bash
sudo ./netxfw plugin load bpf/plugins/out/my_filter.bpf.o 2
```

#### 移除插件
从指定索引移除插件：

```bash
sudo ./netxfw plugin remove 2
```

## 插件开发最佳实践

### 1. 性能优化
- 尽可能减少插件内的循环和复杂计算
- 使用预分配的 BPF 映射避免动态内存分配
- 考虑使用 Per-CPU 映射减少锁竞争

### 2. 安全考虑
- 始终验证数据包长度，防止越界访问
- 避免无限循环，确保程序总能在有限时间内终止
- 使用 `bpf_skb_load_bytes()` 安全地访问数据包内容

### 3. 错误处理
- 当数据包格式无效时返回 `XDP_PASS`，让后续处理决定
- 记录调试信息使用 `bpf_printk()`（仅用于调试）

### 4. 与主程序协作
- 使用 BPF 映射与主程序共享状态
- 遵循主程序的数据结构定义
- 在适当的时候调用 `bpf_tail_call()` 返回主流程

## 高级功能

### 1. 自定义统计

插件可以使用自己的 BPF 映射来记录统计数据：

```c
// 在插件中定义映射
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} my_stats SEC(".maps");

SEC("xdp")
int my_advanced_filter(struct xdp_md *ctx) {
    // ... 处理逻辑 ...
    
    // 更新统计信息
    __u32 key = 0;
    __u64 *count = bpf_map_lookup_elem(&my_stats, &key);
    if (count) (*count)++;
    
    return XDP_PASS;
}
```

### 2. 外部配置

插件可以从用户空间接收配置参数：

```c
// 配置映射
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
        // 根据配置执行特定逻辑
        return XDP_PASS;
    }
    
    return XDP_PASS;
}
```

## 调试技巧

### 1. 日志输出
使用 `bpf_printk()` 输出调试信息（需要 root 权限查看）：

```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

### 2. 验证插件
使用 bpftool 检查加载的插件：

```bash
sudo bpftool prog show
sudo bpftool map show
```

## 限制与注意事项

1. **程序复杂度**: XDP 程序受 verifier 限制，不能过于复杂
2. **内存访问**: 严格遵守数据包边界检查
3. **资源限制**: BPF 映射大小和程序指令数有限制
4. **兼容性**: 不同内核版本的 BPF 特性可能略有差异

## 示例插件

项目中的 `bpf/plugins/` 目录包含多个示例插件，可作为开发参考。

## 故障排除

- **Verifier 错误**: 检查数据包边界访问和循环复杂度
- **加载失败**: 确认插件索引在有效范围内（2-15）
- **性能下降**: 检查插件逻辑复杂度和映射操作频率