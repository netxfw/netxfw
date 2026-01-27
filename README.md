# netxfw — The eXtensible eBPF Firewall

[![License](https://img.shields.io/badge/license-GPLv2-blue.svg)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/livp123/netxfw)](https://goreportcard.com/report/github.com/livp123/netxfw)

> **轻量 · 可扩 · 一令封网**  
> 基于 eBPF/XDP 的高性能主机防火墙，专为中小团队设计。  
> 无需 iptables，无需复杂配置，5 分钟部署，秒级阻断 SSH 暴力破解、端口扫描等攻击。

---

## ✨ 为什么选择 netxfw？

- ✅ **极致性能**：在网卡驱动层丢包（XDP），CPU 开销 <1%，支持百万 PPS  
- ✅ **开箱即用**：单二进制文件，无依赖，`sudo ./netxfw run` 即可运行  
- ✅ **智能多网卡**：自动保护所有物理网卡，跳过 `lo`/`docker0` 等虚拟接口  
- ✅ **全局黑名单**：一次封禁，全网卡生效  
- ✅ **可观测**：内置 Prometheus 指标，轻松对接 Grafana  
- ✅ **可扩展**：YAML 规则 + 插件架构（未来支持 Rust/Zig 多语言运行时）  
- 🌆 **成都验证**：已在华为云（成都 region）、天府软件园多台服务器稳定运行

---

## 🚀 快速开始

### 1. 下载（Linux x86_64）
```bash
wget https://github.com/livp123/netxfw/releases/latest/download/netxfw-linux-amd64 -O netxfw
chmod +x netxfw