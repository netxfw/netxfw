# netxfw — 可扩展的 eBPF 防火墙

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![BPF License](https://img.shields.io/badge/BPF-Dual%20BSD/GPL-purple.svg)](bpf/LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/netxfw/netxfw)](https://goreportcard.com/report/github.com/netxfw/netxfw)
[![Release](https://img.shields.io/github/v/release/netxfw/netxfw)](https://github.com/netxfw/netxfw/releases)
[![English README](https://img.shields.io/badge/README-English-blue.svg)](README_en.md)

> **轻量 · 高性能 · 易扩展**
> 基于 eBPF/XDP 的下一代 Linux 主机防火墙。

`netxfw` 是一款利用现代 Linux 内核 eBPF 技术构建的高性能防火墙。它在网络驱动层（XDP）直接处理数据包，能够以极低的 CPU 开销阻断大规模 DDoS 攻击、暴力破解和非法扫描。

---

## 📋 目录

- [✨ 核心特性](#-核心特性)
- [⚙️ 核心配置](#️-核心配置)
- [🏗️ 架构概览](#️-架构概览)
- [🚀 快速开始](#-快速开始)
- [🔧 系统维护与更新](#-系统维护与更新)
- [📚 相关文档](#-相关文档)

---

## ✨ 核心特性

### 性能优势
- 🚀 **极致性能**：在网卡驱动层（XDP）直接丢弃恶意包，绕过内核网络栈，CPU 占用极低。
- 🌍 **全协议支持**：原生支持 IPv4 和 IPv6，支持 CIDR 网段封禁。
- ⚡ **动态黑名单**：引入基于 `LRU_HASH` 的高速单 IP 匹配机制，专为拦截高频变化的恶意 IP 设计。

### 安全防护
- 🛡️ **细粒度规则**：支持 IP+端口 级别的 Allow/Deny 规则，满足复杂业务需求。
- 🤖 **自动拦截 (Auto-Blocking)**：**防御 DDoS 的利器**。当 IP 触发限速阈值时，系统可自动将其加入动态黑名单，实现内核级的毫秒级封禁。支持配置拦截时长，利用 LRU 特性自动淘汰。
- 🛡️ **安全加固**：
  - **Bogon 过滤**：自动识别并丢弃来自保留/私有 IP 地址段的恶意流量。
  - **严格 TCP 校验**：校验 TCP 标志位组合，有效防御 Null Scan、Xmas Scan 等探测攻击。
  - **分片保护**：支持配置丢弃所有 IP 分片包，防御分片攻击。
  - **SYN 洪水防御**：支持仅对 SYN 包应用限速，确保在遭遇 SYN Flood 时正常业务不受影响。

### 高可用性
- ⚡ **无损热重载**：支持运行时调整 Map 容量并热重载程序，通过状态迁移确保业务零中断。
  - **增量更新 (Incremental)**: 当 Map 容量未变更时，直接更新现有 Map，避免全量迁移，实现毫秒级重载。
  - **全量迁移 (Full Migration)**: 当容量变更时，自动迁移旧 Map 数据到新 Map，确保连接跟踪和规则不丢失。

### 流量控制
- 🌊 **流量整形**：内置基于令牌桶算法的 IP 级别限速与 ICMP 限速。引入 **O(1) 配置缓存** 机制，避免了每个数据包的复杂查找。
- 🧠 **有状态检测 (Conntrack)**：内置高效的连接追踪引擎，自动放行已建立连接的回包。

### 扩展性
- 🧩 **插件化架构 (SDK)**：
  - **Plugin SDK**: 提供标准化的 Go 接口 (`sdk.Plugin`)，允许开发者轻松扩展防火墙功能。
  - **CEL 规则引擎**: 集成 Google CEL 表达式语言，支持对日志进行复杂的 JSON/KV 解析和正则匹配 (`JSON()`, `KV()`, `Match()`)。
  - **动态加载**: 支持通过 eBPF Tail Call 动态加载第三方插件。详情请参考 [插件开发指南](docs/plugins/plugins.md)。
  - **插件间通信 (IPC)**:
    - **EventBus**: 基于发布/订阅模式的事件总线，实现插件解耦通信（如日志引擎 -> AI 分析）。
    - **KV Store**: 共享的内存键值存储 (`sdk.Store`)，用于插件间共享运行时上下文（如威胁情报、信任分）。

### 管理与监控
- 📊 **可观测性**：内置 Web 管理界面（默认 11811 端口）与 Prometheus Exporter，实时监控丢包速率与活跃连接。
- 🏗️ **模块化设计**：BPF 代码采用模块化结构（Filter, Ratelimit, Conntrack, Protocols），逻辑清晰，易于维护。
- 🛠️ **命令行控制**：极简的 CLI 操作，支持动态加载规则和插件，无需重启服务。
- 🔄 **手动更新**：支持通过 `netxfw system update` 一键检测并升级二进制文件。
- 💾 **规则导入导出**：支持多种格式（JSON、YAML、CSV、Binary）的规则导入导出，便于备份和迁移。
  - **文本格式**：简单的 IP 列表或 IP:Port:Action 格式
  - **JSON/YAML**：结构化数据格式，包含黑名单、白名单和 IP+Port 规则
  - **CSV**：表格格式，便于在 Excel 等工具中编辑
  - **Binary (.bin.zst)**：高性能二进制格式，使用 zstd 压缩，适合大规模规则存储

---

## ⚙️ 核心配置

在配置文件（默认为 `/etc/netxfw/config.yaml`）中启用自动拦截功能：

```yaml
rate_limit:
  enabled: true
  auto_block: true          # 开启自动拦截
  auto_block_expiry: "5m"   # 自动拦截的时长，支持 s, m, h
  rules:
    - ip: "0.0.0.0/0"
      rate: 1000            # 每秒包数限制
      burst: 2000           # 允许的最大突发
```

---

## 🏗️ 架构概览

`netxfw` 采用控制面与数据面分离的架构：

### 数据面 (eBPF/XDP/TC)
- **XDP**：在网络驱动层进行极速包过滤（统一 IPv4/IPv6 LPM 匹配、连接追踪状态检查）。
- **TC (Egress)**：在流量出站时更新连接追踪状态。
- **优化**：使用 `Per-CPU Map` 存储统计信息，消除多核竞争。

### 控制面 (Go)
- **Manager**：负责 BPF 程序的加载、固定（Pinning）及生命周期管理。
- **State Migrator**：实现热重载期间的 BPF Map 数据无缝迁移。
- **Web UI**：提供极简的可视化管理界面，查看实时统计与活跃连接。
- **CLI/API**：提供用户交互接口。
- **Metrics**：暴露 Prometheus 监控指标。

---

## 🚀 快速开始

### 1. 安装方式

#### 方式 A：直接下载二进制文件（推荐）
从 [Releases](https://github.com/netxfw/netxfw/releases) 页面下载：

- **x86_64 (amd64)**:
  ```bash
  wget https://github.com/netxfw/netxfw/releases/latest/download/netxfw_Linux_x86_64.tar.gz
  ```
- **ARM64 (aarch64)**:
  ```bash
  wget https://github.com/netxfw/netxfw/releases/latest/download/netxfw_Linux_arm64.tar.gz
  ```

**安装**:
```bash
tar -zxvf netxfw_Linux_*.tar.gz
sudo mv netxfw /usr/local/bin/
```

#### 方式 B：从源码构建

**使用的开发环境**：
- Linux Kernel >= 6.x
- Go >= 1.22

**安装编译工具**：
```bash
# Debian/Ubuntu
sudo apt-get install -y clang llvm libelf-dev libbpf-dev make
```

**编译**:
```bash
git clone https://github.com/netxfw/netxfw.git
cd netxfw
make generate
make
```

### 2. 运行

#### 🚀 XDP 运行模式与自适应降级
`netxfw` 支持 XDP 的多种运行模式，并根据硬件驱动支持情况自动尝试加载，按性能排序：
- **Offloaded (`xdp_hw`)**: 硬件卸载模式，直接在网卡 SOC 上执行，不占用主机 CPU，性能最强。
- **Native (`xdp_drv`)**: 本地驱动模式，在驱动接收路径直接处理，性能极佳。
- **Generic (`xdp_skb`)**: 通用模式，由内核模拟（SKB 之后），无需驱动支持，兼容性最强（适用于云服务器/虚拟机）。

> **💡 性能提示**: 即使在性能最低的 `Generic` 模式下，由于 eBPF 使用了高效的 Map（哈希表）进行 O(1) 匹配，其吞吐量和大规模规则拦截效率依然远高于传统的 `iptables`（基于 O(N) 链式线性匹配）。

```bash
# 使用默认配置加载并执行自适应加载
sudo netxfw system load
```

---

## 🔧 系统维护与更新

### 手动更新 (默认)
为了系统稳定性，`netxfw` 默认不会自动更新。你可以通过以下命令随时检测并升级到最新版本：
```bash
sudo netxfw system update
```

### 开启自动更新 (可选)
如果你作为实验性用途，希望系统每天自动检查并安装更新，可以使用安装脚本显式开启：
```bash
curl -sSL https://raw.githubusercontent.com/netxfw/netxfw/main/scripts/deploy.sh | sudo bash -s -- --enable-auto-update
```

### 卸载

```bash
# 卸载防火墙并移除 BPF 程序
sudo netxfw system unload
```

---

## 📚 相关文档

### 核心文档
- [架构设计](docs/architecture.md) - 详细的系统架构设计文档
- [命令行手册](docs/cli/cli.md) - 完整的 CLI 命令参考
- [插件开发指南](docs/plugins/plugins.md) - 插件开发详细指南

### 特性文档
- [接口特定 Agent 模式](docs/features/interface_specific_agent.md) - 针对特定接口的 Agent 模式配置
- [单机版架构](docs/standalone/) - 单机版详细配置和使用说明

### 开发与测试
- [贡献指南](CONTRIBUTING.md) - 如何为项目做贡献
- [安全策略](SECURITY.md) - 安全漏洞报告指南
- [行为准则](CODE_OF_CONDUCT.md) - 社区行为准则
- [变更日志](CHANGELOG.md) - 详细的版本变更记录

### 其他资源
- [API 参考](docs/api/reference.md) - API 接口详细文档
- [性能基准测试](docs/performance/benchmarks.md) - 性能测试结果和基准
- [云环境支持](docs/cloud/realip.md) - 云环境配置指南
- [完整文档索引](docs/INDEX.md) - 完整的文档目录和导航

---

## 📄 开源协议

本项目采用混合许可证：

- **Go 用户空间代码**: [Apache-2.0](LICENSE)
- **BPF 内核代码**: [Dual BSD/GPL](bpf/LICENSE) (BSD-2-Clause OR GPL-2.0-only)

详见 [NOTICE](NOTICE) 文件了解许可证结构。
