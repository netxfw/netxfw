# NetXFW 文档

欢迎访问 NetXFW 文档。本文档目录包含 NetXFW 项目的所有文档，按类别组织。

---

## 📋 文档导航

### 🚀 快速入门
- [单机版安装与配置](./standalone/) - 单机版快速部署和基本配置
- [命令行手册](./cli/cli.md) - CLI 命令详解与使用示例

### 🏗️ 架构与设计
- [架构概览](./architecture.md) - 系统整体架构设计
- [单机版架构](./standalone/architecture.md) - 单机版详细架构说明
- [包过滤流程](./standalone/PACKET_FILTER_FLOW.md) - 数据包过滤处理流程

### 🔧 开发与扩展
- [插件开发指南](./plugins/plugins.md) - 插件开发框架和接口说明
- [XDP 插件开发](./plugins/xdp/development_guide.md) - XDP 层插件开发指南
- [Go 插件开发](./plugins/golang/development_guide.md) - Go 语言插件开发指南
- [API 参考](./api/reference.md) - API 接口详细参考

### 📊 性能与监控
- [性能基准测试](./performance/benchmarks.md) - 性能测试数据和基准
- [Web API 指标统一](./unified_web_api_metrics.md) - 统一的 Web API 指标设计

### ☁️ 云环境与特殊场景
- [云环境真实 IP](./cloud/realip.md) - 云环境中获取真实客户端 IP
- [接口特定 Agent 模式](./features/interface_specific_agent.md) - 针对特定接口的 Agent 模式

### 🔧 系统管理
- [配置管理统一](./config_management_unification.md) - 配置管理的统一方案
- [测试指南](./testing/TESTING.md) - 测试方法和流程
- [日志引擎](./log-engine/README.md) - 日志处理引擎说明

### 📈 项目评估
- [项目评估报告](./evaluation.md) - 项目的详细评估报告

---

## 📚 目录结构

| 目录 | 说明 |
|------|------|
| [standalone/](./standalone/) | 单机版部署和配置文档 |
| [cluster/](./cluster/) | 集群版文档 (开发中) |
| [api/](./api/) | API 参考文档 |
| [cli/](./cli/) | 命令行工具文档 |
| [plugins/](./plugins/) | 插件开发相关文档 |
| [testing/](./testing/) | 测试相关文档 |
| [performance/](./performance/) | 性能基准和测试文档 |
| [cloud/](./cloud/) | 云环境支持文档 |
| [features/](./features/) | 特性功能文档 |
| [log-engine/](./log-engine/) | 日志引擎相关文档 |

---

## 🌐 双语文档

我们提供中英双语文档以方便不同用户群体：

| 文档类型 | 中文 | 英文 |
|----------|------|------|
| 架构设计 | [architecture.md](./architecture.md) | [architecture_en.md](./architecture_en.md) |
| CLI 命令 | [cli/cli.md](./cli/cli.md) | [cli/cli_en.md](./cli/cli_en.md) |
| 插件开发 | [plugins/plugins.md](./plugins/plugins.md) | [plugins/plugins_en.md](./plugins/plugins_en.md) |
| 性能基准 | [performance/benchmarks.md](./performance/benchmarks.md) | [performance/benchmarks_en.md](./performance/benchmarks_en.md) |
| 云环境支持 | [cloud/realip.md](./cloud/realip.md) | [cloud/realip_en.md](./cloud/realip_en.md) |
| 项目评估 | [evaluation.md](./evaluation.md) | [evaluation_en.md](./evaluation_en.md) |
| 特性文档 | [features/interface_specific_agent.md](./features/interface_specific_agent.md) | [features/interface_specific_agent_en.md](./features/interface_specific_agent_en.md) |

---

## 📖 文档状态

| 类别 | 中文 | 英文 | 完整度 |
|------|------|------|--------|
| 架构设计 | ✅ | ✅ | 完整 |
| CLI 命令 | ✅ | ✅ | 完整 |
| 插件开发 | ✅ | ✅ | 完整 |
| API 参考 | ✅ | - | 仅中文 |
| 性能基准 | ✅ | ✅ | 完整 |
| 云环境支持 | ✅ | ✅ | 完整 |
| 项目评估 | ✅ | ✅ | 完整 |
| 测试指南 | ✅ | - | 仅中文 |

---

## 🚀 快速开始

1. **新手入门**：从 [单机版文档](./standalone/) 开始了解基础概念和部署
2. **日常操作**：参考 [命令行手册](./cli/cli.md) 进行日常管理操作
3. **深度定制**：通过 [插件开发指南](./plugins/plugins.md) 实现功能扩展
4. **性能调优**：查阅 [性能基准测试](./performance/benchmarks.md) 优化系统性能
5. **云端部署**：参考 [云环境文档](./cloud/) 进行云端环境配置

> **说明**: 中文为默认文档 (无后缀)，英文为辅助文档 (_en.md 后缀)。核心文档均已提供双语版本。
