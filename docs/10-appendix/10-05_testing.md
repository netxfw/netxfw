# netxfw 测试策略与用例说明

## 测试概述

netxfw 采用多层次测试策略，包括单元测试、集成测试、性能基准测试和热重载测试，确保系统在各种场景下的稳定性和性能。

## 测试分类

### 1. 功能测试

#### 1.1 攻击模拟测试
- **文件**: `test/verify_attack.py`
- **功能**: 模拟高速攻击流量，验证系统在高压下的表现
- **测试内容**:
  - 每秒数千数据包的处理能力
  - 防火墙规则的有效性
  - 系统资源使用情况

#### 1.2 混合审批流程测试
- **文件**: `test/verify_hybrid_approval.go`
- **功能**: 测试手动和自动规则添加的工作流程
- **测试场景**:
  - 手动添加规则并立即激活
  - 外部告警自动激活规则
  - 手动添加规则并保持待审批状态

### 2. 集成测试

#### 2.1 CLI 命令集成测试
- **文件**: `cmd/netxfw/commands/root_test.go`, `cmd/netxfw/commands/agent/integration_test.go`
- **功能**: 测试 CLI 命令的完整执行流程
- **测试内容**:
  - 根命令和子命令的执行
  - 规则管理命令（添加、删除、列表）
  - 快捷命令（block, allow, unlock）
  - 端口、限速、安全、系统命令
  - 命令行参数解析和错误处理

#### 2.2 插件系统测试
- 验证插件加载、卸载功能
- 测试插件与主系统的交互
- 验证插件间的兼容性

#### 2.3 集群功能测试
- 验证多节点规则同步
- 测试故障转移机制
- 验证负载均衡策略

### 3. 性能基准测试

#### 3.1 SDK 性能基准测试
- **文件**: `pkg/sdk/mock/mock_benchmark_test.go`
- **测试内容**:
  - SDK 创建性能
  - 黑名单/白名单操作性能
  - 规则操作性能
  - 统计获取性能
  - 并发操作性能

#### 3.2 API 处理器基准测试
- **文件**: `internal/api/handlers_benchmark_test.go`
- **测试内容**:
  - 健康检查处理器性能
  - 统计信息处理器性能
  - 配置处理器性能
  - 连接跟踪处理器性能
  - JSON 编解码性能
  - 并发 API 请求性能

#### 3.3 XDP 适配器基准测试
- **文件**: `internal/xdp/adapter_benchmark_test.go`
- **测试内容**:
  - Mock Manager 创建性能
  - 黑名单/白名单操作性能
  - IP+端口规则操作性能
  - 限速规则操作性能
  - 并发操作性能

#### 3.4 性能统计基准测试
- **文件**: `internal/xdp/performance_stats_benchmark_test.go`
- **测试内容**:
  - PerformanceStats 创建性能
  - Map 操作记录性能
  - 统计检索性能
  - 并发读写性能

#### 3.5 配置缓存基准测试
- **文件**: `internal/core/benchmark_test.go`
- **测试内容**:
  - 配置加载性能
  - 配置更新性能
  - 延迟保存性能

### 4. 配置热重载测试

#### 4.1 配置缓存热重载测试
- **文件**: `internal/core/config_cache_hot_reload_test.go`
- **测试内容**:
  - 基本热重载功能
  - 多次连续更新
  - 错误时回滚
  - 并发读取测试
  - 强制重新加载
  - 脏标志跟踪
  - 延迟保存功能
  - 多字段更新
  - 临时文件测试

#### 4.2 同步设置热重载测试
- **测试内容**:
  - DefaultDeny 设置同步
  - EnableAFXDP 设置同步
  - EnableRateLimit 设置同步
  - DropFragments 设置同步
  - StrictTCP 设置同步
  - SYNLimit 设置同步
  - BogonFilter 设置同步

### 5. 吞吐量测试
- 验证系统在高流量下的处理能力
- 测试不同包大小的处理效率
- 验证并发连接处理能力

### 6. 延迟测试
- 测量数据包处理延迟
- 验证系统响应时间
- 测试规则更新的实时性

## 测试执行

### 运行功能测试
```bash
# 运行攻击模拟测试
sudo python3 test/verify_attack.py

# 运行混合审批流程测试
go run test/verify_hybrid_approval.go
```

### 运行单元测试
```bash
# 运行所有单元测试
go test ./...

# 运行特定包的测试
go test ./internal/core/... -v

# 运行热重载测试
go test ./internal/core/... -v -run "TestConfigCache_HotReload"
```

### 运行性能基准测试
```bash
# 运行所有基准测试
go test ./... -bench=. -benchmem -run=^$

# 运行 SDK 基准测试
go test ./pkg/sdk/mock/... -bench=. -benchmem -run=^$

# 运行 API 基准测试
go test ./internal/api/... -bench=. -benchmem -run=^$

# 运行 XDP 基准测试
go test ./internal/xdp/... -bench=. -benchmem -run=^$

# 运行配置缓存基准测试
go test ./internal/core/... -bench=. -benchmem -run=^$
```

### 运行集成测试
```bash
# 启动netxfw守护进程
sudo ./netxfw daemon

# 运行集成测试脚本
# (具体的集成测试脚本位置)
```

### 运行热重载验证脚本
```bash
# 运行热重载验证脚本
sudo ./test/integration/verify_hot_reload.sh
```

## 测试环境要求

- 网络接口: 至少一个活动的网络接口用于测试
- 权限: 大多数测试需要root权限运行
- 内核版本: 支持eBPF/XDP的Linux内核 (推荐 4.18+)
- 硬件: 推荐多核CPU以测试并发性能

## 测试报告

测试结果应记录以下信息:
- 通过/失败状态
- 执行时间
- 资源使用情况 (CPU, 内存)
- 性能指标 (TPS, 延迟)
- 错误日志

## 基准测试结果示例

以下是在 Intel Xeon Gold 6240 @ 2.60GHz 上的典型基准测试结果：

### SDK 操作性能
| 操作 | 延迟 | 内存分配 |
|------|------|----------|
| SDK 创建 | ~18 ns/op | 0 B/op |
| 黑名单添加 | ~10 µs/op | ~2.5 KB/op |
| 白名单添加 | ~11 µs/op | ~2.8 KB/op |
| 统计获取 | ~8 µs/op | ~2.3 KB/op |

### API 处理性能
| 端点 | 延迟 | 内存分配 |
|------|------|----------|
| /health | ~8 µs/op | ~6 KB/op |
| /api/stats | ~33 µs/op | ~10 KB/op |
| /api/config | ~7 µs/op | ~5 KB/op |
| /version | ~10 µs/op | ~6 KB/op |

### 配置缓存性能
| 操作 | 延迟 | 内存分配 |
|------|------|----------|
| LoadConfig | ~16 ns/op | 0 B/op |
| UpdateConfig | ~30 ns/op | 0 B/op |
| SaveConfigDelayed | ~500 ns/op | ~144 B/op |

## 持续集成

所有测试应在以下环境下运行:
- GitHub Actions CI
- 代码提交前本地验证
- 发布前完整回归测试