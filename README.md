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

- [🚀 快速开始](#-快速开始)
- [⚡ 快速命令参考](#-快速命令参考)
- [✨ 核心特性](#-核心特性)
- [⚙️ 核心配置](#️-核心配置)
- [🏗️ 架构概览](#️-架构概览)
- [ 系统维护与更新](#-系统维护与更新)
- [📚 相关文档](#-相关文档)

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

```bash
# 使用默认配置加载并执行自适应加载
sudo netxfw system load
```

---

## ⚡ 快速命令参考

### 基础操作

```bash
# 白名单管理
sudo netxfw allow 192.168.1.100           # 添加 IP 到白名单
sudo netxfw allow add 10.0.0.1            # 添加 IP 到白名单（子命令形式）
sudo netxfw allow list                    # 列出白名单
sudo netxfw allow port list               # 列出 IP+Port 允许规则

# 黑名单管理
sudo netxfw deny 192.168.1.100            # 添加 IP 到静态黑名单
sudo netxfw deny add 10.0.0.1 --ttl 1h    # 添加到动态黑名单（1小时后自动过期）
sudo netxfw deny list                     # 列出所有黑名单
sudo netxfw deny list --dynamic           # 仅列出动态黑名单
sudo netxfw deny port list                # 列出 IP+Port 拒绝规则

# 动态黑名单管理（支持别名 dyn）
sudo netxfw dynamic add 192.168.1.100 --ttl 1h   # 添加动态黑名单
sudo netxfw dyn del 192.168.1.100                # 删除动态黑名单（使用别名）
sudo netxfw dynamic list                         # 列出动态黑名单

# 规则管理
sudo netxfw rule add 192.168.1.0/24 --action deny  # 添加规则
sudo netxfw rule list                              # 列出规则
sudo netxfw rule del 192.168.1.0/24                # 删除规则（支持 delete/remove 别名）
sudo netxfw rule export rules.yaml                 # 导出规则
sudo netxfw rule import rules.yaml                 # 导入规则

# 端口规则管理（IP+Port 级别控制）
sudo netxfw allow 192.168.1.100:8080     # 允许特定 IP+端口
sudo netxfw deny 10.0.0.1:443            # 拒绝特定 IP+端口
sudo netxfw rule add 192.168.1.100:8080 --action allow   # 添加 IP+Port 允许规则
sudo netxfw rule add 10.0.0.1:443 --action deny          # 添加 IP+Port 拒绝规则
sudo netxfw rule del 192.168.1.100:8080                  # 删除 IP+Port 规则

# 开放端口管理（全局端口白名单）
sudo netxfw port add 80                  # 开放 80 端口
sudo netxfw port add 443                 # 开放 443 端口
sudo netxfw port add 8080-8090           # 开放端口范围
sudo netxfw port del 8080                # 移除端口（支持 delete/remove 别名）

# 限速管理
sudo netxfw limit add 0.0.0.0/0 --rate 1000 --burst 2000  # 添加限速规则
sudo netxfw limit list                                     # 列出限速规则

# 系统管理
sudo netxfw system load                   # 加载 XDP 程序
sudo netxfw system unload                 # 卸载 XDP 程序
sudo netxfw system status                 # 查看运行状态
sudo netxfw system reload                 # 热重载配置

# 监控
sudo netxfw status                        # 查看防火墙状态
sudo netxfw conntrack                     # 查看连接跟踪表
sudo netxfw perf show                     # 查看性能统计
```

### Shell 自动补全

```bash
# Bash
netxfw completion bash > /etc/bash_completion.d/netxfw
source ~/.bashrc

# Zsh
netxfw completion zsh > "${fpath[1]}/_netxfw"

# Fish
netxfw completion fish > ~/.config/fish/completions/netxfw.fish
```

---

## ✨ 核心特性

### 性能优势
- 🚀 **极致性能**：在网卡驱动层（XDP）直接丢弃恶意包，绕过内核网络栈，CPU 占用极低。
- 🌍 **全协议支持**：原生支持 IPv4 和 IPv6，支持 CIDR 网段封禁。
- ⚡ **动态黑名单**：引入基于 `LRU_HASH` 的高速单 IP 匹配机制，专为拦截高频变化的恶意 IP 设计。
- 💾 **内存优化**：使用 sync.Pool 对象池技术，减少高频操作的 GC 压力，提升性能 30-50%。

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

---

## ⚙️ 核心配置

### 自动拦截配置

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

### BPF Map 容量配置

根据内存环境调整 Map 容量：

```yaml
capacity:
  whitelist: 10000          # 白名单容量
  blacklist: 50000          # 静态黑名单容量
  dynamic_blacklist: 20000  # 动态黑名单容量
  conntrack: 100000         # 连接跟踪表容量
```

### 日志引擎配置

日志引擎用于实时分析日志文件并自动执行防御动作：

```yaml
log_engine:
  enabled: true             # 启用日志引擎
  workers: 4                # 并发处理协程数
  files:                    # 监控的日志文件列表
    - "/var/log/nginx/access.log"
    - "/var/log/auth.log"
    - "/var/log/syslog"
  rules:
    # SSH 爆破防御：60秒内失败5次则封禁
    - id: "ssh_bruteforce"
      path: "/var/log/auth.log"
      action: "dynblack"    # 动态封禁（默认5分钟）
      is: ["Failed password"]
      threshold: 5
      interval: 60

    # 拦截恶意爬虫
    - id: "block_scrapers"
      path: "/var/log/nginx/access.log"
      action: "dynblack:1h" # 封禁1小时
      or:
        - "Go-http-client"
        - "python-requests"
        - "curl/"

    # Nginx 404/500 高频扫描
    - id: "nginx_scan"
      path: "/var/log/nginx/access.log"
      action: "dynblack"
      expression: |
        (Fields()[8] == "404" || Fields()[8] == "500") &&
        Contains(Fields()[6], "admin") &&
        Count(30) > 10
```

**日志引擎动作说明**：

| 动作值 | 字符串形式 | 说明 |
|--------|------------|------|
| `0` | `log` | 仅记录告警，不执行拦截 |
| `1` | `dynblack` | 动态封禁（默认过期时间） |
| `1` | `dynblack:1h` | 动态封禁指定时长（如 10m, 1h, 30s） |
| `2` | `lock` / `deny` | 永久封禁（需手动解封） |

> **提示**: 动作支持数字形式（0/1/2）或字符串形式，两种写法等效。

更多配置请参考 [日志引擎文档](docs/log-engine/07-03_log_engine.md)。

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
- [架构设计](docs/02-01_architecture.md) - 详细的系统架构设计文档
- [命令行手册](docs/cli/03-01_cli.md) - 完整的 CLI 命令参考
- [插件开发指南](docs/plugins/04-01_plugins.md) - 插件开发详细指南

### 配置与优化
- [BPF Map 容量配置](docs/06-03_bpf_map_capacity.md) - 内存优化和容量配置指南
- [性能调优指南](docs/10-01_performance_tuning.md) - 性能优化详细指南
- [故障排查指南](docs/09-01_troubleshooting.md) - 常见问题诊断和解决方案
- [安全最佳实践](docs/11-01_security_best_practices.md) - 生产环境安全配置指南

### 特性文档
- [接口特定 Agent 模式](docs/features/05-03_interface_specific_agent.md) - 针对特定接口的 Agent 模式配置
- [单机版架构](docs/standalone/) - 单机版详细配置和使用说明
- [规则导入导出](docs/03-03_rule_import_export.md) - 规则导入导出功能详解

### 开发与测试
- [贡献指南](CONTRIBUTING.md) - 如何为项目做贡献
- [安全策略](SECURITY.md) - 安全漏洞报告指南
- [行为准则](CODE_OF_CONDUCT.md) - 社区行为准则
- [变更日志](CHANGELOG.md) - 详细的版本变更记录

### 其他资源
- [API 参考](docs/api/04-05_api_reference.md) - API 接口详细文档
- [OpenAPI 规范](docs/api/openapi.yaml) - OpenAPI 3.0 规范文件
- [性能基准测试](docs/performance/06-01_benchmarks.md) - 性能测试结果和基准
- [云环境支持](docs/cloud/05-01_realip.md) - 云环境配置指南
- [完整文档索引](docs/INDEX.md) - 完整的文档目录和导航

---

## 📄 开源协议

本项目采用混合许可证：

- **Go 用户空间代码**: [Apache-2.0](LICENSE)
- **BPF 内核代码**: [Dual BSD/GPL](bpf/LICENSE) (BSD-2-Clause OR GPL-2.0-only)

详见 [NOTICE](NOTICE) 文件了解许可证结构。
