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
- 🧠 **智能检测**：自动识别所有物理网卡，无需手动配置接口名称。
- 📊 **可观测性**：内置 Prometheus Exporter，实时监控丢包速率与流量趋势。
- 🛠️ **一令封网**：极简的 CLI 操作，支持动态加载规则，无需重启服务。
- 📦 **云原生友好**：支持 YAML 配置，易于与现有运维体系集成。

---

## 🏗️ 架构概览

`netxfw` 由两部分组成：
1.  **内核态 (eBPF/XDP)**：高性能数据面，负责根据白名单和锁定列表进行极速过滤。
2.  **用户态 (Go)**：控制面，负责规则解析、网卡管理、API 服务及 Prometheus 指标暴露。

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
# Prometheus 指标端口
metrics_port: 9100

# 白名单网段 (CIDR 格式)
whitelist:
  - 127.0.0.1/32
  - 192.168.1.0/24

# 锁定列表网段 (CIDR 格式)
lock_list_file: "/etc/netxfw/lock.conf"

# 动态规则 (后续扩展)
rules:
  - name: "ssh_protection"
    port: 22
    threshold: 10
    duration: "1h"
```

### 3. 常用操作

| 命令 | 说明 | 示例 |
| :--- | :--- | :--- |
| `lock` | 封禁指定 IP/网段 | `sudo netxfw lock 1.2.3.4` |
| `unlock` | 解封指定 IP/网段 | `sudo netxfw unlock 1.2.3.4` |
| `allow` | 将 IP/网段加入白名单 | `sudo netxfw allow 1.2.3.4` |
| `unallow` | 将 IP/网段从白名单移除 | `sudo netxfw unallow 1.2.3.4` |
| `list` | 查看当前封禁列表及统计 | `sudo netxfw list` |
| `allow-list` | 查看当前白名单列表 | `sudo netxfw allow-list` |
| `import` | 从文件批量导入锁定列表 | `sudo netxfw import ips.txt` |
| `unload` | 卸载 XDP 程序 | `sudo netxfw unload xdp` |

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
- [x] CLI 动态封禁/解封
- [x] Prometheus 指标暴露
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
