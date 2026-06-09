---
layout: default
title: NetXFW Documentation
---

# NetXFW 文档中心

欢迎使用 NetXFW - 基于 eBPF/XDP 的高性能防火墙

## 📚 文档导航

### 🚀 快速开始
- [文档指南](01-getting-started/01-00_document_guide.md) - 从这里开始！
- [项目介绍](01-getting-started/01-01_project_introduction.md) - 什么是 NetXFW
- [快速导航](01-getting-started/index.md) - 快速访问入口

### 📖 完整文档目录

#### [入门指南](01-getting-started/)
- 文档指南
- 项目介绍
- 快速导航

#### [安装部署](02-installation/)
- [安全最佳实践](02-installation/02-01_security_best_practices.md) - 安装前的安全配置

#### [快速上手](03-quick-start/)
- [CLI 命令手册](03-quick-start/03-01_cli.md) - 命令行使用指南
- [规则导入导出](03-quick-start/03-02_rule_import_export.md) - 批量规则管理

#### [配置优化](04-configuration/)
- [性能调优](04-configuration/04-01_performance_tuning.md) - 配置优化指南
- [BPF Map 容量](04-configuration/04-02_bpf_map_capacity.md) - 调整系统容量

#### [高级功能](05-advanced-features/)
- [Real IP 支持](05-advanced-features/05-01_realip.md) - Proxy Protocol 支持
- [接口指定](05-advanced-features/05-02_interface_specific_agent.md) - 指定网络接口
- [日志引擎](05-advanced-features/05-03_log_engine.md) - 基于日志的自动防护
- [动态模块](05-advanced-features/05-04_dynamic_modules.md) - 动态模块顺序
- [健康检查](05-advanced-features/05-05_health_check.md) - 健康检查系统
- [性能监控](05-advanced-features/05-06_performance_monitoring.md) - 性能监控

#### [插件开发](06-plugin-development/)
- [插件系统](06-plugin-development/06-01_plugins.md) - 插件开发基础
- [XDP 开发指南](06-plugin-development/06-02_xdp_development_guide.md) - XDP 开发指南
- [Golang 开发指南](06-plugin-development/06-03_golang_development_guide.md) - Golang 开发指南

#### [性能测试](07-testing/)
- [性能回归测试](07-testing/07-03_performance_regression.md) - 性能回归测试报告

#### [故障排查](08-troubleshooting/)
- [故障排查指南](08-troubleshooting/08-01_troubleshooting.md) - 常见问题解决

#### [API 参考](09-api-reference/)
- [配置管理统一化](09-api-reference/09-01_config_management_unification.md)
- [统一 Web API 指标](09-api-reference/09-02_unified_web_api_metrics.md)
- [API 参考](09-api-reference/09-03_api_reference.md)

#### [附录](10-appendix/)
- [架构概览](10-appendix/10-01_architecture.md)
- [架构设计图](10-appendix/10-02_architecture_diagrams.md)
- [数据包过滤流程](10-appendix/10-03_packet_filter_flow.md)
- [数据包过滤总结](10-appendix/10-04_summary_packet_filter.md)
- [测试文档](10-appendix/10-05_testing.md)
- [评估报告](10-appendix/10-06_evaluation.md)
- [架构交互图](netxfw_architecture.html) - 架构设计交互图
- [代码库可视化](codebase_visualizer.html) - 交互式代码流浏览器
- [开发与项目使用指南](dev-project-use.md) - 开发者指南

---

## 🌐 English Documentation

- [Documentation Guide](01-getting-started/01-00_document_guide_en.md)
- [Project Introduction](01-getting-started/01-01_project_introduction_en.md)
- [Quick Navigation](01-getting-started/index_en.md)
- [Interactive Architecture](netxfw_architecture_en.html) - Architecture diagram (English)
- [Codebase Visualizer](codebase_visualizer_en.html) - Interactive code flow browser (English)
- [Dev & Project Use Guide](dev-project-use_en.md) - Developer guide (English)

---

## 📋 关于本文档

NetXFW 是一款利用现代 Linux 内核 eBPF 技术构建的高性能防火墙。它在网络驱动层（XDP）直接处理数据包，能够以极低的 CPU 开销阻断大规模 DDoS 攻击、暴力破解和非法扫描。

更多信息请访问：[GitHub 仓库](https://github.com/netxfw/netxfw)
