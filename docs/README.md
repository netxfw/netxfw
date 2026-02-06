# netxfw 文档目录

## 概述
netxfw 是一个基于 eBPF/XDP 的高性能网络防火墙系统，采用"控制面 (Go) + 数据面 (eBPF/XDP)"架构。

## 文档结构

### 单机版文档 (Standalone)
- [standalone/](./standalone/) - 单机版专用文档
  - [PACKET_FILTER_FLOW.md](./standalone/PACKET_FILTER_FLOW.md) - BPF过滤流程详解
  - [SUMMARY_PACKET_FILTER.md](./standalone/SUMMARY_PACKET_FILTER.md) - 过滤流程简明摘要

### 核心概念
- [architecture.md](./architecture.md) - 系统架构设计与版本规划
- [plugins.md](./plugins.md) - 插件开发指南

### API文档
- [api/](./api/) - API参考文档
  - [reference.md](./api/reference.md) - API端点参考

### 插件开发文档
- [plugins/](./plugins/) - 插件开发
  - [xdp/](./plugins/xdp/) - XDP插件开发
    - [development_guide.md](./plugins/xdp/development_guide.md) - XDP插件开发指南
  - [golang/](./plugins/golang/) - Go插件开发
    - [development_guide.md](./plugins/golang/development_guide.md) - Go插件开发指南

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