# 应用服务层重构计划

## 背景

应用服务层 (`internal/app/`) 包含一些工具函数（`ops_*.go`），这些函数的职责不够清晰，应该移至更合适的包中。

## 当前问题

### 文件分布

```
internal/app/
├── rule/              # ✅ 规则服务（职责清晰）
├── config/            # ✅ 配置服务（职责清晰）
├── plugin/            # ✅ 插件服务（职责清晰）
├── ops_util.go        # ⚠️ 工具函数（应移至 utils/）
├── ops_xdp.go         # ⚠️ XDP 操作（应移至 datapath/）
├── ops_config.go      # ⚠️ 配置操作（应移至 config/）
├── ops_stats.go       # ⚠️ 统计操作（应移至 stats/）
├── ops_env.go         # ⚠️ 环境操作（应移至 utils/）
└── ops_daemon.go      # ⚠️ 守护进程操作（应移至 daemon/）
```

### 影响范围

- **ops_util.go**: 25 个文件使用
- **ops_xdp.go**: 8 个文件使用
- **ops_config.go**: 31 个文件使用

## 重构策略

### 阶段 1: 创建门面函数（低风险）

**目标**: 保留现有 API，内部委托给新的实现

```go
// internal/app/ops_util.go
package app

import (
    "github.com/netxfw/netxfw/internal/utils/xdputil"
)

// Deprecated: Use xdputil.GetAttachedInterfaceInfos() instead.
func GetAttachedInterfaceInfos() ([]InterfaceXDPInfo, error) {
    return xdputil.GetAttachedInterfaceInfos()
}
```

**优点**:
- 不破坏现有代码
- 提供迁移路径
- 可以渐进式重构

### 阶段 2: 创建新的包结构（低风险）

**目标**: 在新位置创建实现

```
internal/utils/
├── xdputil/
│   └── interface.go    # XDP 接口工具
├── configutil/
│   └── loader.go       # 配置加载工具
└── envutil/
    └── runtime.go      # 环境工具

internal/datapath/
└── xdp/
    └── operations.go   # XDP 操作

internal/metrics/
└── stats/
    └── loader.go       # 统计加载
```

### 阶段 3: 标记废弃（低风险）

**目标**: 标记旧函数为废弃

```go
// Deprecated: Use xdputil.GetAttachedInterfaceInfos() instead.
// This function will be removed in v3.0.
func GetAttachedInterfaceInfos() ([]InterfaceXDPInfo, error) {
    return xdputil.GetAttachedInterfaceInfos()
}
```

### 阶段 4: 迁移调用方（中风险）

**目标**: 逐步迁移调用方到新 API

```bash
# 查找所有调用方
grep -r "app\.GetAttachedInterfaceInfos" --include="*.go"

# 逐个文件迁移
# 1. 修改导入
# 2. 修改函数调用
# 3. 运行测试
```

### 阶段 5: 删除旧代码（高风险）

**目标**: 删除所有废弃函数

**前提条件**:
- 所有调用方已迁移
- 所有测试通过
- 文档已更新

## 实施步骤

### 第 1 步: 创建新包（本周）

```bash
# 创建新包
mkdir -p internal/utils/xdputil
mkdir -p internal/utils/configutil
mkdir -p internal/utils/envutil

# 创建实现文件
touch internal/utils/xdputil/interface.go
touch internal/utils/configutil/loader.go
touch internal/utils/envutil/runtime.go
```

### 第 2 步: 实现新函数（本周）

```go
// internal/utils/xdputil/interface.go
package xdputil

import (
    datapathlifecycle "github.com/netxfw/netxfw/internal/datapath/xdp/lifecycle"
)

type InterfaceXDPInfo = datapathlifecycle.InterfaceXDPInfo

func GetAttachedInterfaceInfos(pinPath string) ([]InterfaceXDPInfo, error) {
    return datapathlifecycle.GetAttachedInterfacesWithInfo(pinPath)
}
```

### 第 3 步: 添加废弃标记（下周）

```go
// internal/app/ops_util.go
package app

import (
    "github.com/netxfw/netxfw/internal/utils/xdputil"
)

// Deprecated: Use xdputil.GetAttachedInterfaceInfos() instead.
// This function will be removed in v3.0.
func GetAttachedInterfaceInfos() ([]InterfaceXDPInfo, error) {
    return xdputil.GetAttachedInterfaceInfos(GetPinPath())
}
```

### 第 4 步: 更新文档（下周）

创建迁移指南：

```markdown
# API 迁移指南

## 已废弃的函数

### app.GetAttachedInterfaceInfos()

**新 API**: `xdputil.GetAttachedInterfaceInfos(pinPath string)`

**迁移示例**:
```go
// 旧代码
infos, err := app.GetAttachedInterfaceInfos()

// 新代码
infos, err := xdputil.GetAttachedInterfaceInfos(app.GetPinPath())
```
```

### 第 5 步: CI 检查（下周）

添加 CI 检查，防止使用废弃函数：

```yaml
# .github/workflows/check-deprecated.yml
name: Check Deprecated API Usage

on: [push, pull_request]

jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Check deprecated usage
        run: |
          if grep -r "app\.GetAttachedInterfaceInfos" --include="*.go" | grep -v "ops_util.go"; then
            echo "Error: Found usage of deprecated function"
            exit 1
          fi
```

## 风险评估

### 低风险

- ✅ 创建新包
- ✅ 实现新函数
- ✅ 添加废弃标记
- ✅ 更新文档

### 中风险

- ⚠️ 迁移调用方（需要仔细测试）

### 高风险

- 🔴 删除旧代码（需要确保所有调用方已迁移）

## 时间表

| 阶段 | 时间 | 风险 | 状态 |
|------|------|------|------|
| 创建新包 | 第 1 周 | 低 | ⏸️ 待开始 |
| 实现新函数 | 第 1 周 | 低 | ⏸️ 待开始 |
| 添加废弃标记 | 第 2 周 | 低 | ⏸️ 待开始 |
| 迁移调用方 | 第 2-4 周 | 中 | ⏸️ 待开始 |
| 删除旧代码 | 第 5 周 | 高 | ⏸️ 待开始 |

## 成功标准

- ✅ 所有新代码有单元测试
- ✅ 所有废弃函数有文档说明
- ✅ CI 检查通过
- ✅ 无破坏性变更
- ✅ 所有调用方已迁移

## 回滚计划

如果出现问题，可以：

1. 恢复旧的函数实现
2. 移除废弃标记
3. 更新文档

## 相关文档

- [API 迁移指南](./10-03_api_migration_guide.md)
- [废弃策略](./10-03_api_migration_guide.md)
- [版本兼容性](./10-03_api_migration_guide.md)
