# NetXFW 文档索引

## 文档编号说明

| 编号范围 | 类别 | 说明 |
|----------|------|------|
| 01-xx | 快速入门 | 安装部署和基本使用 |
| 02-xx | 架构设计 | 系统架构和技术原理 |
| 03-xx | 核心功能 | CLI 命令和核心特性 |
| 04-xx | 扩展开发 | 插件开发和 API |
| 05-xx | 云环境 | 云部署和特殊配置 |
| 06-xx | 监控性能 | 性能优化和监控 |
| 07-xx | 系统管理 | 配置管理和运维 |
| 08-xx | 项目评估 | 项目评估报告 |

---

## 01. 快速入门

| 编号 | 文档 | 说明 |
|------|------|------|
| 01-01 | [README](./01-01_README.md) | 文档中心主页 |
| 01-02 | [README (EN)](./01-02_README_en.md) | Documentation Center (English) |

---

## 02. 架构设计

| 编号 | 文档 | 说明 |
|------|------|------|
| 02-01 | [架构概览](./02-01_architecture.md) | 系统整体架构设计 |
| 02-02 | [Architecture Overview](./02-02_architecture_en.md) | System architecture (English) |
| 02-03 | [单机版架构](./standalone/02-03_architecture_diagrams.md) | 单机版详细架构说明 |
| 02-04 | [Architecture Diagrams (EN)](./standalone/02-03_architecture_diagrams_en.md) | Standalone architecture (English) |
| 02-05 | [包过滤流程](./standalone/02-04_PACKET_FILTER_FLOW.md) | 数据包过滤处理流程 |
| 02-06 | [包过滤流程摘要](./standalone/02-05_SUMMARY_PACKET_FILTER.md) | 数据包过滤流程摘要 |

---

## 03. 核心功能

| 编号 | 文档 | 说明 |
|------|------|------|
| 03-01 | [命令行手册](./cli/03-01_cli.md) | CLI 命令详解与使用示例 |
| 03-02 | [CLI Reference](./cli/03-02_cli_en.md) | CLI command reference (English) |
| 03-03 | [规则导入导出](./03-03_rule_import_export.md) | 规则导入导出功能详解 |
| 03-04 | [Rule Import/Export (EN)](./03-04_rule_import_export_en.md) | Rule import/export (English) |

---

## 04. 扩展开发

| 编号 | 文档 | 说明 |
|------|------|------|
| 04-01 | [插件开发指南](./plugins/04-01_plugins.md) | 插件开发框架和接口说明 |
| 04-02 | [Plugin Development (EN)](./plugins/04-02_plugins_en.md) | Plugin development (English) |
| 04-03 | [XDP 插件开发](./plugins/xdp/04-03_xdp_development_guide.md) | XDP 层插件开发指南 |
| 04-04 | [Go 插件开发](./plugins/golang/04-04_golang_development_guide.md) | Go 语言插件开发指南 |
| 04-05 | [API 参考](./api/04-05_api_reference.md) | API 接口详细参考 |
| 04-06 | [API Reference (EN)](./api/04-05_api_reference_en.md) | API interface reference (English) |

---

## 05. 云环境部署

| 编号 | 文档 | 说明 |
|------|------|------|
| 05-01 | [云环境真实 IP](./cloud/05-01_realip.md) | 云环境中获取真实客户端 IP |
| 05-02 | [Real IP in Cloud (EN)](./cloud/05-02_realip_en.md) | Getting real client IP (English) |
| 05-03 | [接口特定 Agent 模式](./features/05-03_interface_specific_agent.md) | 针对特定接口的 Agent 模式 |
| 05-04 | [Interface-specific Agent (EN)](./features/05-04_interface_specific_agent_en.md) | Interface-specific agent (English) |

---

## 06. 监控与性能

| 编号 | 文档 | 说明 |
|------|------|------|
| 06-01 | [性能基准测试](./performance/06-01_benchmarks.md) | 性能测试数据和基准 |
| 06-02 | [Performance Benchmarks (EN)](./performance/06-02_benchmarks_en.md) | Performance benchmarks (English) |
| 06-03 | [BPF Map 容量配置](./06-03_bpf_map_capacity.md) | BPF Map 容量配置指南 |
| 06-04 | [BPF Map Capacity (EN)](./06-04_bpf_map_capacity_en.md) | BPF Map capacity (English) |

---

## 07. 系统管理

| 编号 | 文档 | 说明 |
|------|------|------|
| 07-01 | [配置管理统一](./07-01_config_management_unification.md) | 配置管理的统一方案 |
| 07-02 | [Config Management (EN)](./07-01_config_management_unification_en.md) | Config management (English) |
| 07-03 | [Web API 指标统一](./07-02_unified_web_api_metrics.md) | 统一的 Web API 指标设计 |
| 07-04 | [Web API Metrics (EN)](./07-02_unified_web_api_metrics_en.md) | Web API metrics (English) |
| 07-05 | [日志引擎](./log-engine/07-03_log_engine.md) | 日志处理引擎说明 |
| 07-06 | [Log Engine (EN)](./log-engine/07-03_log_engine_en.md) | Log engine (English) |
| 07-07 | [测试指南](./testing/07-04_TESTING.md) | 测试方法和流程 |
| 07-08 | [Testing Guide (EN)](./testing/07-04_TESTING_en.md) | Testing guide (English) |

---

## 08. 项目评估

| 编号 | 文档 | 说明 |
|------|------|------|
| 08-01 | [项目评估报告](./08-01_evaluation.md) | 项目的详细评估报告 |
| 08-02 | [Project Evaluation (EN)](./08-02_evaluation_en.md) | Project evaluation (English) |

---

## 09. 故障排查

| 编号 | 文档 | 说明 |
|------|------|------|
| 09-01 | [故障排查指南](./09-01_troubleshooting.md) | 常见问题诊断和解决方案 |
| 09-02 | [Troubleshooting Guide (EN)](./09-02_troubleshooting_en.md) | Troubleshooting guide (English) |

---

## 10. 性能调优

| 编号 | 文档 | 说明 |
|------|------|------|
| 10-01 | [性能调优指南](./10-01_performance_tuning.md) | 性能优化详细指南 |
| 10-02 | [Performance Tuning (EN)](./10-02_performance_tuning_en.md) | Performance tuning (English) |

---

## 11. 安全最佳实践

| 编号 | 文档 | 说明 |
|------|------|------|
| 11-01 | [安全最佳实践](./11-01_security_best_practices.md) | 生产环境安全配置指南 |
| 11-02 | [Security Best Practices (EN)](./11-02_security_best_practices_en.md) | Security best practices (English) |

---

## 12. API 规范

| 编号 | 文档 | 说明 |
|------|------|------|
| 12-01 | [OpenAPI 规范](./api/openapi.yaml) | OpenAPI 3.0 规范文件 |

---

## 文档统计

| 类别 | 中文 | 英文 | 合计 |
|------|------|------|------|
| 快速入门 | 1 | 1 | 2 |
| 架构设计 | 4 | 2 | 6 |
| 核心功能 | 2 | 2 | 4 |
| 扩展开发 | 4 | 2 | 6 |
| 云环境部署 | 2 | 2 | 4 |
| 监控与性能 | 2 | 2 | 4 |
| 系统管理 | 4 | 4 | 8 |
| 项目评估 | 1 | 1 | 2 |
| 故障排查 | 1 | 1 | 2 |
| 性能调优 | 1 | 1 | 2 |
| 安全最佳实践 | 1 | 1 | 2 |
| API 规范 | 0 | 1 | 1 |
| **总计** | **23** | **20** | **43** |

---

## 新手指南

如果您是初次接触 NetXFW，建议按以下顺序阅读文档：

1. **01-01 [README](./01-01_README.md)** - 了解项目概述
2. **02-01 [架构概览](./02-01_architecture.md)** - 理解系统架构
3. **03-01 [命令行手册](./cli/03-01_cli.md)** - 学习基本操作
4. **06-01 [性能基准测试](./performance/06-01_benchmarks.md)** - 了解性能特点
5. **06-03 [BPF Map 容量配置](./06-03_bpf_map_capacity.md)** - 配置内存参数
