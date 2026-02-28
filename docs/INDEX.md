# NetXFW 文档索引

## 📚 完整文档目录

### 🚀 快速入门
- [README](./README.md) - 文档中心主页
- [单机版快速入门](./standalone/README.md) - 单机版部署和基本配置
- [架构概览](./architecture.md) - 系统整体架构设计
- [命令行手册](./cli/cli.md) - CLI 命令详解与使用示例

### 🏗️ 架构设计
- [架构概览](./architecture.md) - 系统整体架构设计
- [架构概览（英文）](./architecture_en.md) - System architecture overview (English)
- [单机版架构](./standalone/architecture.md) - 单机版详细架构说明
- [包过滤流程](./standalone/PACKET_FILTER_FLOW.md) - 数据包过滤处理流程
- [配置管理统一](./config_management_unification.md) - 配置管理的统一方案
- [Web API 指标统一](./unified_web_api_metrics.md) - 统一的 Web API 指标设计

### 🔧 核心功能
- [命令行手册](./cli/cli.md) - CLI 命令详解与使用示例
- [命令行手册（英文）](./cli/cli_en.md) - CLI command reference (English)
- [动态黑名单机制](./standalone/DYNAMIC_BLACKLIST.md) - 动态黑名单技术细节
- [热重载机制](./standalone/HOT_RELOAD.md) - 热重载和状态迁移技术细节
- [流量整形](./standalone/RATE_LIMIT.md) - 限速和流量整形技术细节
- [规则导入导出](./rule_import_export.md) - 规则导入导出功能详解
- [规则导入导出（英文）](./rule_import_export_en.md) - Rule import/export feature (English)

### 🧩 扩展开发
- [插件开发指南](./plugins/plugins.md) - 插件开发框架和接口说明
- [插件开发指南（英文）](./plugins/plugins_en.md) - Plugin development guide (English)
- [XDP 插件开发](./plugins/xdp/development_guide.md) - XDP 层插件开发指南
- [Go 插件开发](./plugins/golang/development_guide.md) - Go 语言插件开发指南
- [API 参考](./api/reference.md) - API 接口详细参考

### 🛡️ 安全与防护
- [安全加固策略](./standalone/SECURITY_HARDENING.md) - 安全加固相关策略
- [DDoS 防护](./standalone/DDOS_PROTECTION.md) - DDoS 攻击防护机制
- [TCP 校验机制](./standalone/TCP_CHECK.md) - TCP 标志位校验机制

### ☁️ 云环境部署
- [云环境真实 IP](./cloud/realip.md) - 云环境中获取真实客户端 IP
- [云环境真实 IP（英文）](./cloud/realip_en.md) - Getting real client IP in cloud environments (English)
- [接口特定 Agent 模式](./features/interface_specific_agent.md) - 针对特定接口的 Agent 模式
- [接口特定 Agent 模式（英文）](./features/interface_specific_agent_en.md) - Interface-specific agent mode (English)

### 📊 监控与性能
- [性能基准测试](./performance/benchmarks.md) - 性能测试数据和基准
- [性能基准测试（英文）](./performance/benchmarks_en.md) - Performance benchmarks (English)
- [Web UI 介绍](./standalone/WEB_UI.md) - Web 管理界面功能介绍
- [Prometheus 集成](./standalone/PROMETHEUS_INTEGRATION.md) - Prometheus 指标导出

### 🔧 系统管理
- [配置管理统一](./config_management_unification.md) - 配置管理的统一方案
- [测试指南](./testing/TESTING.md) - 测试方法和流程
- [日志引擎](./log-engine/README.md) - 日志处理引擎说明
- [部署脚本说明](./standalone/DEPLOYMENT_SCRIPTS.md) - 部署相关脚本说明

### 📈 项目评估
- [项目评估报告](./evaluation.md) - 项目的详细评估报告
- [项目评估报告（英文）](./evaluation_en.md) - Project evaluation report (English)

---

## 🔍 按功能查找

### 安装部署
- [单机版安装](./standalone/README.md)
- [命令行工具](./cli/cli.md)
- [部署脚本](./standalone/DEPLOYMENT_SCRIPTS.md)

### 开发扩展
- [插件开发](./plugins/plugins.md)
- [API 参考](./api/reference.md)
- [XDP 插件](./plugins/xdp/development_guide.md)

### 性能优化
- [性能基准](./performance/benchmarks.md)
- [热重载机制](./standalone/HOT_RELOAD.md)
- [流量整形](./standalone/RATE_LIMIT.md)

### 安全防护
- [DDoS 防护](./standalone/DDOS_PROTECTION.md)
- [安全加固](./standalone/SECURITY_HARDENING.md)
- [TCP 校验](./standalone/TCP_CHECK.md)

### 监控运维
- [Web UI](./standalone/WEB_UI.md)
- [Prometheus 集成](./standalone/PROMETHEUS_INTEGRATION.md)
- [日志引擎](./log-engine/README.md)

---

## 🌐 双语对照

所有核心文档均提供中英文版本，方便不同用户群体阅读：

| 主题 | 中文文档 | 英文文档 |
|------|----------|----------|
| 架构设计 | [architecture.md](./architecture.md) | [architecture_en.md](./architecture_en.md) |
| 命令行 | [cli/cli.md](./cli/cli.md) | [cli/cli_en.md](./cli/cli_en.md) |
| 插件开发 | [plugins/plugins.md](./plugins/plugins.md) | [plugins/plugins_en.md](./plugins/plugins_en.md) |
| 云环境 | [cloud/realip.md](./cloud/realip.md) | [cloud/realip_en.md](./cloud/realip_en.md) |
| 性能基准 | [performance/benchmarks.md](./performance/benchmarks.md) | [performance/benchmarks_en.md](./performance/benchmarks_en.md) |
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

## 🚀 新手指南

如果您是初次接触 NetXFW，建议按以下顺序阅读文档：

1. **[README](./README.md)** - 了解项目概述
2. **[单机版快速入门](./standalone/README.md)** - 快速部署和体验
3. **[架构概览](./architecture.md)** - 理解系统架构
4. **[命令行手册](./cli/cli.md)** - 学习基本操作
5. **[Web UI 介绍](./standalone/WEB_UI.md)** - 了解图形化管理
6. **[性能基准测试](./performance/benchmarks.md)** - 了解性能特点