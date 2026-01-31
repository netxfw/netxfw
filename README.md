# netxfw — The eXtensible eBPF Firewall

[![License](https://img.shields.io/badge/license-GPLv3-blue.svg)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/livp123/netxfw)](https://goreportcard.com/report/github.com/livp123/netxfw)
[![Release](https://img.shields.io/github/v/release/livp123/netxfw)](https://github.com/livp123/netxfw/releases)

> **轻量 · 高性能 · 易扩展**
> 基于 eBPF/XDP 的下一代 Linux 主机防火墙。

`netxfw` 是一款利用现代 Linux 内核 eBPF 技术构建的高性能防火墙。它在网络驱动层（XDP）直接处理数据包，能够以极低的 CPU 开销阻断大规模 DDoS 攻击、暴力破解和非法扫描。

---

## ✨ 核心特性

- 🚀 **极致性能**：在网卡驱动层（XDP）直接丢弃恶意包，绕过内核网络栈，CPU 占用极低。
- 🌍 **全协议支持**：原生支持 IPv4 和 IPv6，支持 CIDR 网段封禁。
- 🧠 **有状态检测 (Conntrack)**：内置高效的连接追踪引擎，自动放行已建立连接的回包。
- 🛡️ **细粒度规则**：支持 IP+端口 级别的 Allow/Deny 规则，满足复杂业务需求。
- ⚡ **无损热重载**：支持运行时调整 Map 容量并热重载程序，通过状态迁移确保业务零中断。
- 🌊 **流量整形**：内置基于令牌桶算法的 ICMP 限速，有效抵御 ICMP Flood 攻击。
- 📊 **可观测性**：内置 Prometheus Exporter，实时监控丢包速率与流量趋势。
- 🛠️ **一令封网**：极简的 CLI 操作，支持动态加载规则，无需重启服务。

---

## 🏗️ 架构概览

`netxfw` 采用控制面与数据面分离的架构：
1.  **数据面 (eBPF/XDP/TC)**：
    - **XDP**：在网络驱动层进行极速包过滤（LPM 匹配、连接追踪状态检查）。
    - **TC (Egress)**：在流量出站时更新连接追踪状态。
2.  **控制面 (Go)**：
    - **Manager**：负责 BPF 程序的加载、固定（Pinning）及生命周期管理。
    - **State Migrator**：实现热重载期间的 BPF Map 数据无缝迁移。
    - **CLI/API**：提供用户交互接口。
    - **Metrics**：暴露 Prometheus 监控指标。

---

## 🚀 快速开始

### 1. 安装方式

#### 方式 A：直接下载二进制文件（推荐）
从 [Releases](https://github.com/livp123/netxfw/releases) 页面下载适用于您架构的最新版本：

- **x86_64 (amd64)**:
  ```bash
  wget https://github.com/livp123/netxfw/releases/download/v0.2.2/netxfw_Linux_x86_64.tar.gz
  ```
- **ARM64 (aarch64)**:
  ```bash
  wget https://github.com/livp123/netxfw/releases/download/v0.2.2/netxfw_Linux_arm64.tar.gz
  ```

**安装**:
```bash
tar -zxvf netxfw_Linux_*.tar.gz
sudo mv netxfw /usr/local/bin/
```

#### 方式 B：从源码构建

**环境要求**：
- Linux Kernel >= 5.4 (推荐 5.10+)
- Go >= 1.21

**安装编译工具**：

- **Ubuntu / Debian**:
  ```bash
  sudo apt-get update
  sudo apt-get install -y clang llvm libelf-dev libbpf-dev make
  # 如果是 x86_64 架构编译 eBPF
  sudo apt-get install -y gcc-multilib
  ```

- **CentOS / RHEL / Fedora**:
  ```bash
  # CentOS 8+ / RHEL 8+
  sudo dnf install -y clang llvm elfutils-libelf-devel libbpf-devel make gcc
  ```

**编译步骤**：
```bash
git clone https://github.com/livp123/netxfw.git
cd netxfw
make generate
make build
sudo make install
```

### 2. 运行与配置

#### 启动服务
```bash
# 方式 A：直接运行
sudo netxfw load xdp

# 方式 B：作为 Systemd 服务运行
sudo systemctl start netxfw
sudo systemctl enable netxfw
```

#### 配置文件示例 (`/etc/netxfw/config.yaml`)
```yaml
# 全局基础配置
base:
  metrics_port: 9100
  default_deny: true       # 开启默认拒绝模式
  allow_icmp: true         # 允许 ICMP
  enable_conntrack: true   # 开启连接追踪
  persist_rules: true      # 规则持久化

# 容量动态调整 (无需重新编译)
capacity:
  conntrack: 200000        # 连接追踪表容量
  whitelist: 50000         # 白名单容量
  lock_list: 100000        # 黑名单容量

# 端口白名单
port:
  allowed_ports:
    - 22
    - 80
    - 443
  # IP+端口 细粒度规则
  ip_port_rules:
    - ip: "1.2.3.4"
      port: 8080
      action: 1 # 1:allow, 2:deny
```

### 3. 常用操作

| 命令 | 说明 | 示例 |
| :--- | :--- | :--- |
| `rule add <ip> <port> <allow/deny>` | 添加 IP+端口 规则 | `sudo netxfw rule add 1.2.3.4 80 allow` |
| `rule lock <ip>` | 全局封禁指定 IP/网段 | `sudo netxfw rule lock 1.2.3.4` |
| `rule allow <ip>` | 将 IP/网段加入全局白名单 | `sudo netxfw rule allow 1.2.3.4` |
| `rule list rules` | 查看当前所有 IP+Port 规则 | `sudo netxfw rule list rules` |
| `rule list conntrack` | 查看当前活跃连接 (Conntrack) | `sudo netxfw rule list conntrack` |
| `reload` | 热重载配置并更新 XDP 程序 | `sudo netxfw reload` |
| `load xdp` | 加载 XDP 程序 | `sudo netxfw load xdp` |
| `unload xdp` | 卸载 XDP 程序 | `sudo netxfw unload xdp` |

---

## 📈 监控集成

`netxfw` 默认在 `9100` 端口暴露 Prometheus 指标。

**关键指标**：
- `netxfw_xdp_drop_total`: 被防火墙拦截的总包数。
- `netxfw_xdp_pass_total`: 通过防火墙的总包数。
- `netxfw_locked_ips_count`: 当前被封禁的 IP 数量。

您可以在 Grafana 中轻松配置仪表盘，实时观测攻击情况。

---

## 🗺️ 路线图 (Roadmap)

- [x] 核心 XDP 过滤引擎 (IPv4/IPv6)
- [x] 有状态连接追踪 (Conntrack)
- [x] IP+Port 细粒度访问控制
- [x] 无损热重载与状态迁移
- [x] 动态容量调整
- [x] Prometheus 指标暴露
- [x] 基于令牌桶的 ICMP 限速
- [ ] 自动化攻击检测引擎 (基于日志/流量)
- [ ] Web 控制台
- [ ] 分布式协同防护 (多机联动)

---

## 🤝 贡献指南

我们非常欢迎任何形式的贡献！无论是提交 Issue、修复 Bug 还是完善文档。
请参阅 [CONTRIBUTING.md](CONTRIBUTING.md) (即将推出)。

---

## 📄 开源协议

本项目采用 [GPL-3.0](LICENSE) 协议开源。
