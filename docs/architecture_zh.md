# netxfw 架构设计

## 概览
`netxfw` 是一个基于 **eBPF (Extended Berkeley Packet Filter)** 和 **XDP (eXpress Data Path)** 构建的高性能可编程防火墙。它运行在 Linux 网络栈的最前端（网卡驱动钩子），能够在数据包到达内核网络栈（`sk_buff` 分配）之前，以极低的 CPU 开销丢弃或重定向数据包。

## 核心组件

### 1. 数据面 (Data Plane - eBPF/XDP)
数据面由 C 语言编写，编译为 BPF 字节码，直接在内核中运行。
*   **位置**: `bpf/`
*   **核心特性**:
    *   **统一 LPM Trie**: 使用单个 128 位最长前缀匹配 (LPM) Trie 同时处理 IPv4 和 IPv6 流量。IPv4 地址在内部被处理为 IPv4 映射的 IPv6 地址 (`::ffff:a.b.c.d`)。
    *   **无锁设计**: 使用 Per-CPU 数组和哈希表存储统计信息，最大程度减少锁竞争。
    *   **XDP 动作**: 支持 `XDP_DROP` (拦截), `XDP_PASS` (放行), 和 `XDP_TX` (回弹 - 计划中)。

### 2. 控制面 (Control Plane - Go Agent)
控制面由 Go 语言编写，运行在用户空间，负责管理 BPF 程序的生命周期并与 BPF Map 交互。
*   **位置**: `cmd/netxfw`, `internal/`
*   **主要职责**:
    *   **加载/卸载**: 使用 `cilium/ebpf` 库加载 XDP 程序并将 Map 固定 (Pin) 到 `/sys/fs/bpf/netxfw`。
    *   **Map 管理**: 对 BPF Map 进行增删改查操作 (添加/移除规则)。
    *   **持久化**: 将内存中的 BPF Map 状态同步到 `/etc/netxfw/rules.deny.txt` 和 `config.yaml`。
    *   **CLI**: 提供用户友好的命令行接口 (`netxfw rule add`, `netxfw system top`)。

## 统一双栈架构
为了简化维护并减少内存占用，`netxfw` 采用了统一 Map 策略：
*   **Map**: `lock_list` (LPM Trie)
*   **Key**: `struct lpm_key` (128 位 IPv6 地址 + 前缀长度)
*   **IPv4 处理**:
    *   用户输入: `192.0.2.1`
    *   内部转换: `::ffff:192.0.2.1`
    *   存储: 存入 128 位 Trie 中。
    *   查找: 进入的 IPv4 数据包在查找前会被构造为 IPv4 映射的 IPv6 Key。

## 目录结构
*   `bpf/`: eBPF 源代码 (`.c`) 和头文件。
*   `cmd/netxfw/`: Go 二进制文件的主入口。
*   `internal/core/`: 规则管理的业务逻辑。
*   `internal/xdp/`: 底层 BPF 交互 (加载, Map 封装)。
*   `rules/`: 默认配置文件。
*   `test/`: 集成测试和单元测试。

## 数据流向
1.  **数据包到达**: 网卡接收数据包 -> XDP 驱动钩子。
2.  **解析**: `filter.bpf.c` 解析以太网 -> IP (v4/v6) -> L4 头部。
3.  **查找**:
    *   检查 `whitelist` (白名单/放行)。
    *   检查 `lock_list` (黑名单/拦截)。
    *   检查 `ip_port_rules` (细粒度规则)。
4.  **决策**:
    *   如果匹配 Deny -> `XDP_DROP` + 增加丢包计数器。
    *   如果无匹配 -> `XDP_PASS` (继续传递给内核协议栈)。

## 持久化模型
*   **运行时**: `/sys/fs/bpf/netxfw/*` (固定的 BPF Maps)。
*   **存储**: `/etc/netxfw/rules.deny.txt` (纯文本列表) & `config.yaml`。
*   **同步**: `netxfw system sync` 命令负责运行时状态与存储之间的双向同步。
