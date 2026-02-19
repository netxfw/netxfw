# NetXFW 文档

欢迎访问 NetXFW 文档。本文档目录包含 NetXFW 项目的所有文档，按类别组织。

## 目录结构

- [standalone/](./standalone/) - 单机版文档
- [cluster/](./cluster/) - 集群版文档 (开发中)
- [api/](./api/) - API 参考文档
- [cli/](./cli/) - 命令行文档
- [plugins/](./plugins/) - 插件开发指南
- [testing/](./testing/) - 测试文档
- [performance/](./performance/) - 性能基准测试
- [cloud/](./cloud/) - 云环境支持文档

## 快速链接

### 架构与设计

| 文档 | 中文 (默认) | 英文 (辅助) |
|------|-------------|-------------|
| 架构概览 | [architecture.md](./architecture.md) | [English](./architecture_en.md) |
| 单机版架构 | [standalone/architecture.md](./standalone/architecture.md) | - |
| 包过滤流程 | [standalone/PACKET_FILTER_FLOW.md](./standalone/PACKET_FILTER_FLOW.md) | - |

### 命令行与 API

| 文档 | 中文 (默认) | 英文 (辅助) |
|------|-------------|-------------|
| CLI 命令 | [cli/cli.md](./cli/cli.md) | [English](./cli/cli_en.md) |
| API 参考 | [api/reference.md](./api/reference.md) | - |

### 插件开发

| 文档 | 中文 (默认) | 英文 (辅助) |
|------|-------------|-------------|
| 插件开发指南 | [plugins/plugins.md](./plugins/plugins.md) | [English](./plugins/plugins_en.md) |
| XDP 插件开发 | [plugins/xdp/development_guide.md](./plugins/xdp/development_guide.md) | - |
| Go 插件开发 | [plugins/golang/development_guide.md](./plugins/golang/development_guide.md) | - |

### 性能与云环境

| 文档 | 中文 (默认) | 英文 (辅助) |
|------|-------------|-------------|
| 性能基准测试 | [performance/benchmarks.md](./performance/benchmarks.md) | [English](./performance/benchmarks_en.md) |
| 云环境真实 IP | [cloud/realip.md](./cloud/realip.md) | [English](./cloud/realip_en.md) |

### 项目评估

| 文档 | 中文 (默认) | 英文 (辅助) |
|------|-------------|-------------|
| 项目评估报告 | [evaluation.md](./evaluation.md) | [English](./evaluation_en.md) |

### 其他文档

- [测试指南](./testing/TESTING.md)
- [日志引擎](./log-engine/README.md)
- [配置管理统一](./config_management_unification.md)
- [Web API 指标统一](./unified_web_api_metrics.md)

## 快速开始

1. 单机版安装配置，请参阅 [单机版文档](./standalone/)
2. 开发插件，请参阅 [插件开发指南](./plugins/)
3. API 集成，请参阅 [API 参考](./api/)
4. 云环境配置，请参阅 [云环境文档](./cloud/)
5. 性能基准，请参阅 [性能文档](./performance/)

## 文档状态

| 类别 | 中文 | 英文 | 状态 |
|------|------|------|------|
| 架构设计 | ✅ | ✅ | 完整 |
| CLI 命令 | ✅ | ✅ | 完整 |
| 插件开发 | ✅ | ✅ | 完整 |
| API 参考 | ✅ | - | 仅中文 |
| 性能基准 | ✅ | ✅ | 完整 |
| 云环境支持 | ✅ | ✅ | 完整 |
| 项目评估 | ✅ | ✅ | 完整 |
| 测试指南 | ✅ | - | 仅英文 |

> **说明**: 中文为默认文档 (无后缀)，英文为辅助文档 (_en.md 后缀)。核心文档均已提供双语版本。
