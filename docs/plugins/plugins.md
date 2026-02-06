# 插件开发指南 (Plugin Development)

`netxfw` 支持通过 eBPF Tail Call 机制动态加载第三方插件。这允许开发者在不修改或重新编译核心防火墙代码的情况下，扩展自定义的数据包处理逻辑。

## 1. 核心原理

`netxfw` 的主 XDP 程序在提取完数据包基本信息后，会尝试跳转到一个名为 `jmp_table` 的 `BPF_MAP_TYPE_PROG_ARRAY`。
- **插件索引**: 插件占据 `jmp_table` 的 `2` 到 `15` 号索引位。
- **核心逻辑**: 如果索引位有程序，则执行插件逻辑；插件执行完毕后，通常应调用 `bpf_tail_call` 返回主程序的协议处理器，或直接返回 `XDP_PASS`/`XDP_DROP`。

## 2. 快速开始

### 环境要求
- 安装 `clang` 和 `llvm`。
- 引入 `netxfw` 的 BPF 头文件。

### 编写插件
创建一个 `.c` 文件（例如 `my_filter.bpf.c`）：

```c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "include/plugin.h"

SEC("xdp")
int my_custom_filter(struct xdp_md *ctx) {
    // 你的逻辑
    // 例如：拦截特定特征的数据包
    
    // 如果想让数据包继续流向 netxfw 核心逻辑
    return XDP_PASS; 
}

char _license[] SEC("license") = "GPL";
```

### 编译插件
使用 `netxfw` 提供的 `Makefile`：
```bash
make plugins
```
编译产物将位于 `bpf/plugins/out/` 目录下。

## 3. 加载与管理

使用 `netxfw` 命令行工具动态管理插件：

### 加载插件
将编译好的 `.o` 文件加载到指定的跳转表索引（例如索引 2）：
```bash
sudo netxfw plugin load ./bpf/plugins/out/my_filter.o 2
```

### 查看状态
目前可以通过 `bpftool` 查看 `jmp_table` 的内容，或通过 `netxfw system status` 查看统计信息。

### 卸载插件
```bash
sudo netxfw plugin remove 2
```

## 4. 最佳实践
- **性能**: 插件运行在 XDP 层，请保持逻辑简洁，避免复杂的循环。
- **安全性**: 插件拥有完整的 XDP 权限，请确保代码经过严格审计。
- **索引管理**: 建议为不同的功能分配固定的索引位，避免冲突。
