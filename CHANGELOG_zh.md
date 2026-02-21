# 变更日志

本项目的所有重要更改都将记录在此文件中。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.0.0/)，并且本项目遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/spec/v2.0.0.html) 语义化版本规范。

## [Unreleased]

## [v1.0.18] - 2026-02-21

### 新增
- **多个版本**: 包含从1.0.9到1.0.18版本的功能和修复
- **增强稳定性**: 各种改进和错误修复
- **性能优化**: 持续的性能改进

## [v1.0.8] - 2025-02-20

### 新增
- **统一 IP Map**: 将 IPv4 和 IPv6 BPF Map 合并为单个 128 位 LPM Trie，以简化维护并提高性能。
- **配置同步**: 添加 `system sync` 命令 (`to-config` / `to-map`)，用于桥接运行时 BPF 状态与配置文件。
- **规则导入**: 恢复 `rule import` 命令，用于批量加载黑名单文件。
- **文档**: 添加了 `ARCHITECTURE.md` (架构)、`CONTRIBUTING.md` (贡献) 和 `SECURITY.md` (安全)，为开源做准备。
- **测试套件**: 将集成测试整理到 `/test/integration` 目录下，并提供自动化脚本。
- **许可证文件**: 添加 Apache-2.0 LICENSE（Go 代码）和 Dual BSD/GPL（BPF 代码）。

### 变更
- **内部架构**: 重构 `internal/xdp`，在内部将 IPv4 地址作为 IPv4 映射的 IPv6 地址 (`::ffff:a.b.c.d`) 处理。
- **CLI**: 改进 `rule list` 输出，正确区分允许/拒绝列表。
- **CLI**: 修复 `rule remove` 命令，确保使用 `system sync` 时更改能持久化到磁盘。
- **CI/CD**: 更新 GitHub Actions 仅运行单元测试，排除需要真实环境的集成测试。

### 修复
- 修复了 `rule list deny` 会显示白名单 IP 的 Bug。
- 修复了 `rule remove` 更改无法跨重启持久化的问题（现在通过 `system sync` 支持）。
- 修复了 `rule import` 的 CLI 参数解析，支持 `deny` 别名。
- 修复了 XDP 加载时间计算，显示实际程序运行时长而非系统运行时长。
- 修复了测试套件中的数据竞争问题，添加了适当的互斥锁保护。

## [v1.0.7] - 2025-02-18

### 新增
- **热重载**: 支持零停机热重载和状态迁移。
- **自动拦截**: 当触发限速阈值时自动封禁 IP。

### 变更
- 改进 BPF Map 管理和清理。

## [v1.0.6] - 2025-02-15

### 新增
- 首次公开发布。
- 核心 XDP/TC 数据包过滤。
- 连接追踪 (Conntrack)。
- 基于令牌桶算法的限速。
- Web 监控界面。
- Prometheus 指标导出器。

---

更早版本请查看 [GitHub Releases](https://github.com/netxfw/netxfw/releases)。
