# netxfw 文档目录

## 概述
netxfw 是一个基于 eBPF/XDP 的高性能网络防火墙系统，采用"控制面 (Go) + 数据面 (eBPF/XDP)"架构。

## 文档结构

### 核心概念
- [architecture.md](./architecture.md) - 系统架构设计与版本规划
- [plugins.md](./plugins.md) - 插件开发指南
- [PACKET_FILTER_FLOW.md](./PACKET_FILTER_FLOW.md) - BPF过滤流程详解
- [SUMMARY_PACKET_FILTER.md](./SUMMARY_PACKET_FILTER.md) - 过滤流程简明摘要

### 使用指南
- [cli.md](./cli.md) - 命令行手册

### 测试相关
- [TESTING.md](./TESTING.md) - 测试策略与用例说明

## 版本说明

netxfw 规划了七个版本以适应不同场景：
- **单机版**: 核心高性能防火墙
- **单机AI版**: 集成TinyML引擎
- **小集群版**: 多节点协同管理
- **小集群AI版**: 集群+AI检测
- **大集群版**: 大规模节点优化
- **大集群AI版**: 分布式AI检测
- **嵌入式版**: 低资源占用版本