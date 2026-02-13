# 变更日志

本项目的所有重要更改都将记录在此文件中。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.0.0/)，并且本项目遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/spec/v2.0.0.html) 语义化版本规范。

## [Unreleased]

### 新增
- **统一 IP Map**: 将 IPv4 和 IPv6 BPF Map 合并为单个 128 位 LPM Trie，以简化维护并提高性能。
- **配置同步**: 添加 `system sync` 命令 (`to-config` / `to-map`)，用于桥接运行时 BPF 状态与配置文件。
- **规则导入**: 恢复 `rule import` 命令，用于批量加载黑名单文件。
- **文档**: 添加了 `ARCHITECTURE.md` (架构)、`CONTRIBUTING.md` (贡献) 和 `SECURITY.md` (安全)，为开源做准备。
- **测试套件**: 将集成测试整理到 `/test/integration` 目录下，并提供自动化脚本。

### 变更
- **内部架构**: 重构 `internal/xdp`，在内部将 IPv4 地址作为 IPv4 映射的 IPv6 地址 (`::ffff:a.b.c.d`) 处理。
- **CLI**: 改进 `rule list` 输出，正确区分允许/拒绝列表。
- **CLI**: 修复 `rule remove` 命令，确保使用 `system sync` 时更改能持久化到磁盘。

### 修复
- 修复了 `rule list deny` 会显示白名单 IP 的 Bug。
- 修复了 `rule remove` 更改无法跨重启持久化的问题（现在通过 `system sync` 支持）。
- 修复了 `rule import` 的 CLI 参数解析，支持 `deny` 别名。

## [v1.0.6] - 2025-XX-XX
- (之前的变更...)
