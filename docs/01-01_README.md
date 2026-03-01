# NetXFW 文档

欢迎访问 NetXFW 文档。本文档目录包含 NetXFW 项目的所有文档，按类别组织。

---

## 📋 文档导航

### 🚀 快速入门
- [单机版安装与配置](./standalone/) - 单机版快速部署和基本配置
- [命令行手册](./cli/03-01_cli.md) - CLI 命令详解与使用示例

### 🏗️ 架构与设计
- [架构概览](./02-01_architecture.md) - 系统整体架构设计
- [单机版架构](./standalone/02-03_architecture_diagrams.md) - 单机版详细架构说明
- [包过滤流程](./standalone/02-04_PACKET_FILTER_FLOW.md) - 数据包过滤处理流程

### 🔧 开发与扩展
- [插件开发指南](./plugins/04-01_plugins.md) - 插件开发框架和接口说明
- [API 参考](./api/04-05_api_reference.md) - API 接口详细参考
- [规则导入导出](./03-03_rule_import_export.md) - 规则导入导出功能详解

### 📊 性能与监控
- [性能基准测试](./performance/06-01_benchmarks.md) - 性能测试数据和基准
- [Web API 指标统一](./07-02_unified_web_api_metrics.md) - 统一的 Web API 指标设计

### ☁️ 云环境与特殊场景
- [云环境真实 IP](./cloud/05-01_realip.md) - 云环境中获取真实客户端 IP
- [接口特定 Agent 模式](./features/05-03_interface_specific_agent.md) - 针对特定接口的 Agent 模式

### 🔧 系统管理
- [配置管理统一](./07-01_config_management_unification.md) - 配置管理的统一方案
- [测试指南](./testing/07-04_TESTING.md) - 测试方法和流程
- [日志引擎](./log-engine/07-03_log_engine.md) - 日志处理引擎说明

### 📈 项目评估
- [项目评估报告](./08-01_evaluation.md) - 项目的详细评估报告

### 🔍 故障排查与优化
- [故障排查指南](./09-01_troubleshooting.md) - 常见问题诊断和解决方案
- [性能调优指南](./10-01_performance_tuning.md) - 性能优化详细指南
- [安全最佳实践](./11-01_security_best_practices.md) - 生产环境安全配置指南

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
| 架构设计 | [02-01_architecture.md](./02-01_architecture.md) | [02-02_architecture_en.md](./02-02_architecture_en.md) |
| CLI 命令 | [cli/03-01_cli.md](./cli/03-01_cli.md) | [cli/03-02_cli_en.md](./cli/03-02_cli_en.md) |
| 插件开发 | [plugins/04-01_plugins.md](./plugins/04-01_plugins.md) | [plugins/04-02_plugins_en.md](./plugins/04-02_plugins_en.md) |
| 规则导入导出 | [03-03_rule_import_export.md](./03-03_rule_import_export.md) | [03-04_rule_import_export_en.md](./03-04_rule_import_export_en.md) |
| 性能基准 | [performance/06-01_benchmarks.md](./performance/06-01_benchmarks.md) | [performance/06-02_benchmarks_en.md](./performance/06-02_benchmarks_en.md) |
| 云环境支持 | [cloud/05-01_realip.md](./cloud/05-01_realip.md) | [cloud/05-02_realip_en.md](./cloud/05-02_realip_en.md) |
| 项目评估 | [08-01_evaluation.md](./08-01_evaluation.md) | [08-02_evaluation_en.md](./08-02_evaluation_en.md) |
| 特性文档 | [features/05-03_interface_specific_agent.md](./features/05-03_interface_specific_agent.md) | [features/05-04_interface_specific_agent_en.md](./features/05-04_interface_specific_agent_en.md) |
| BPF Map 容量 | [06-03_bpf_map_capacity.md](./06-03_bpf_map_capacity.md) | [06-04_bpf_map_capacity_en.md](./06-04_bpf_map_capacity_en.md) |
| 配置管理 | [07-01_config_management_unification.md](./07-01_config_management_unification.md) | [07-01_config_management_unification_en.md](./07-01_config_management_unification_en.md) |
| 测试指南 | [testing/07-04_TESTING.md](./testing/07-04_TESTING.md) | [testing/07-04_TESTING_en.md](./testing/07-04_TESTING_en.md) |
| 日志引擎 | [log-engine/07-03_log_engine.md](./log-engine/07-03_log_engine.md) | [log-engine/07-03_log_engine_en.md](./log-engine/07-03_log_engine_en.md) |
| 故障排查 | [09-01_troubleshooting.md](./09-01_troubleshooting.md) | [09-02_troubleshooting_en.md](./09-02_troubleshooting_en.md) |
| 性能调优 | [10-01_performance_tuning.md](./10-01_performance_tuning.md) | [10-02_performance_tuning_en.md](./10-02_performance_tuning_en.md) |
| 安全最佳实践 | [11-01_security_best_practices.md](./11-01_security_best_practices.md) | [11-02_security_best_practices_en.md](./11-02_security_best_practices_en.md) |

---

## 📖 文档状态

| 类别 | 中文 | 英文 | 完整度 |
|------|------|------|--------|
| 架构设计 | ✅ | ✅ | 完整 |
| CLI 命令 | ✅ | ✅ | 完整 |
| 插件开发 | ✅ | ✅ | 完整 |
| 规则导入导出 | ✅ | ✅ | 完整 |
| API 参考 | ✅ | ✅ | 完整 |
| 性能基准 | ✅ | ✅ | 完整 |
| 云环境支持 | ✅ | ✅ | 完整 |
| 项目评估 | ✅ | ✅ | 完整 |
| 测试指南 | ✅ | ✅ | 完整 |
| 日志引擎 | ✅ | ✅ | 完整 |
| 配置管理 | ✅ | ✅ | 完整 |
| 故障排查 | ✅ | ✅ | 完整 |
| 性能调优 | ✅ | ✅ | 完整 |
| 安全最佳实践 | ✅ | ✅ | 完整 |

---

## 🚀 快速开始

1. **新手入门**：从 [单机版文档](./standalone/) 开始了解基础概念和部署
2. **日常操作**：参考 [命令行手册](./cli/03-01_cli.md) 进行日常管理操作
3. **深度定制**：通过 [插件开发指南](./plugins/04-01_plugins.md) 实现功能扩展
4. **性能调优**：查阅 [性能基准测试](./performance/06-01_benchmarks.md) 优化系统性能
5. **云端部署**：参考 [云环境文档](./cloud/) 进行云端环境配置

> **说明**: 中文为默认文档 (无后缀)，英文为辅助文档 (_en.md 后缀)。核心文档均已提供双语版本。
