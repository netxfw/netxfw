# netxfw — The eXtensible eBPF Firewall

[![License](https://img.shields.io/badge/license-GPLv2-blue.svg)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/livp123/netxfw)](https://goreportcard.com/report/github.com/livp123/netxfw)

> **轻量 · 可扩 · 一令封网**  
> 基于 eBPF/XDP 的高性能主机防火墙，专为中小团队设计。  
> 无需 iptables，无需复杂配置，5 分钟部署，秒级阻断 SSH 暴力破解、端口扫描等攻击。

---

## ✨ 为什么选择 netxfw？

- ✅ **极致性能**：在网卡驱动层丢包（XDP），CPU 开销 <1%，支持百万 PPS  
- ✅ **全协议支持**：完美支持 IPv4 & IPv6 流量阻断  
- ✅ **智能多网卡**：自动保护所有物理网卡，跳过 `lo`/`docker0` 等虚拟接口  
- ✅ **实时统计**：精确记录每个封禁 IP 的丢包次数  
- ✅ **可观测**：内置 Prometheus 指标，轻松对接 Grafana  
- ✅ **可扩展**：YAML 规则 + 命令行实时控制

---

## 🚀 快速开始

### 1. 构建
# 1. 克隆
```
git clone https://github.com/livp123/netxfw.git
cd netxfw
```

# 2. 生成 eBPF 脚手架并构建
make generate
make build

# 3. 安装 (创建 /etc/netxfw/ 目录并配置默认文件)
sudo make install

### 2. 使用方法

#### 启动防火墙服务
默认会加载 `/etc/netxfw/config.yaml`。
```bash
sudo netxfw load xdp
```

#### 配置说明
在 `/etc/netxfw/config.yaml` 中，你可以提前配置：
- `whitelist`: 白名单列表，支持单个 IP 或 CIDR 网段（例如 `192.168.1.0/24`）
- `metrics_port`: Prometheus 指标服务端口（默认 9100）
- `rules`: 动态拦截规则

#### 封禁 IP (支持 IPv4/IPv6)
```bash
sudo ./netxfw lock 1.2.3.4
sudo ./netxfw lock 2001:db8::1
```

#### 查看封禁列表及统计
```bash
sudo ./netxfw list
```

#### 解封 IP
```bash
sudo ./netxfw unlock 1.2.3.4
```

---

## 📖 详细文档
- [命令行手册](docs/cli.md)
- [系统架构](docs/architecture.md)