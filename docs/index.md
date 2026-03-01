---
layout: default
title: NetXFW - eBPF Firewall
---

# netxfw — 可扩展的 eBPF 防火墙

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![BPF License](https://img.shields.io/badge/BPF-Dual%20BSD/GPL-purple.svg)](bpf/LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/netxfw/netxfw)](https://goreportcard.com/report/github.com/netxfw/netxfw)
[![Release](https://img.shields.io/github/v/release/netxfw/netxfw)](https://github.com/netxfw/netxfw/releases)

> **轻量 · 高性能 · 易扩展**
> 基于 eBPF/XDP 的下一代 Linux 主机防火墙。

`netxfw` 是一款利用现代 Linux 内核 eBPF 技术构建的高性能防火墙。它在网络驱动层（XDP）直接处理数据包，能够以极低的 CPU 开销阻断大规模 DDoS 攻击、暴力破解和非法扫描。

---

## 📋 文档导航

### 🚀 快速入门
- [README (中文)](../README.md) - 项目概述和快速开始
- [README (English)](../README_en.md) - Project overview and quick start

### 📚 核心文档

| 文档 | 中文 | English |
|------|------|---------|
| 架构设计 | [架构概览](./02-01_architecture.md) | [Architecture](./02-02_architecture_en.md) |
| 命令行手册 | [CLI 命令](./cli/03-01_cli.md) | [CLI Commands](./cli/03-02_cli_en.md) |
| 插件开发 | [插件开发指南](./plugins/04-01_plugins.md) | [Plugin Guide](./plugins/04-02_plugins_en.md) |
| 规则导入导出 | [规则导入导出](./03-03_rule_import_export.md) | [Rule Import/Export](./03-04_rule_import_export_en.md) |
| 性能基准 | [性能基准测试](./performance/06-01_benchmarks.md) | [Benchmarks](./performance/06-02_benchmarks_en.md) |
| BPF Map 容量 | [容量配置](./06-03_bpf_map_capacity.md) | [Capacity Config](./06-04_bpf_map_capacity_en.md) |
| 日志引擎 | [日志引擎](./log-engine/07-03_log_engine.md) | [Log Engine](./log-engine/07-03_log_engine_en.md) |
| 故障排查 | [故障排查指南](./09-01_troubleshooting.md) | [Troubleshooting](./09-02_troubleshooting_en.md) |
| 性能调优 | [性能调优指南](./10-01_performance_tuning.md) | [Performance Tuning](./10-02_performance_tuning_en.md) |
| 安全最佳实践 | [安全最佳实践](./11-01_security_best_practices.md) | [Security Best Practices](./11-02_security_best_practices_en.md) |

---

## ✨ 核心特性

- 🚀 **极致性能**：在网卡驱动层（XDP）直接丢弃恶意包
- 🌍 **全协议支持**：原生支持 IPv4 和 IPv6
- ⚡ **动态黑名单**：基于 LRU_HASH 的高速匹配
- ��️ **自动拦截**：触发限速阈值时自动封禁
- ⚡ **无损热重载**：运行时调整配置，业务零中断

---

## 🚀 快速开始

\`\`\`bash
# 下载安装
wget https://github.com/netxfw/netxfw/releases/latest/download/netxfw_Linux_x86_64.tar.gz
tar -zxvf netxfw_Linux_*.tar.gz
sudo mv netxfw /usr/local/bin/

# 加载防火墙
sudo netxfw system load

# 基本命令
sudo netxfw allow 192.168.1.100    # 白名单
sudo netxfw deny 10.0.0.1          # 黑名单
sudo netxfw port add 80            # 开放端口
sudo netxfw status                 # 查看状态
\`\`\`

---

## 🔗 相关链接

- [GitHub 仓库](https://github.com/netxfw/netxfw)
- [Releases 下载](https://github.com/netxfw/netxfw/releases)
- [问题反馈](https://github.com/netxfw/netxfw/issues)
