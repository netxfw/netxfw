# API 迁移指南

## 概述

本文档提供了从旧 API 迁移到新 API 的详细指南。所有废弃的 API 都会在文档中标记，并提供迁移示例。

## 已废弃的函数

### 1. app.GetAttachedInterfaceInfos()

**状态**: ⚠️ 已废弃（计划在 v3.0 移除）

**新 API**: `xdputil.GetAttachedInterfaceInfos(pinPath string)`

**迁移示例**:

```go
// ❌ 旧代码（已废弃）
import "github.com/netxfw/netxfw/internal/app"

infos, err := app.GetAttachedInterfaceInfos()
if err != nil {
    // 处理错误
}

// ✅ 新代码
import (
    "github.com/netxfw/netxfw/internal/utils/xdputil"
    "github.com/netxfw/netxfw/internal/app"
)

infos, err := xdputil.GetAttachedInterfaceInfos(app.GetPinPath())
if err != nil {
    // 处理错误
}
```

**迁移时间表**:
- v2.1: 标记为废弃
- v2.2-2.9: 提供迁移警告
- v3.0: 移除旧函数

### 2. app.LogInfo()

**状态**: ⚠️ 已废弃（计划在 v3.0 移除）

**新 API**: `logger.Get(ctx).Infof()`

**迁移示例**:

```go
// ❌ 旧代码（已废弃）
import "github.com/netxfw/netxfw/internal/app"

app.LogInfo(ctx, "Operation completed")

// ✅ 新代码
import "github.com/netxfw/netxfw/internal/utils/logger"

logger.Get(ctx).Infof("Operation completed")
```

### 3. app.Version()

**状态**: ⚠️ 已废弃（计划在 v3.0 移除）

**新 API**: `version.Version`

**迁移示例**:

```go
// ❌ 旧代码（已废弃）
import "github.com/netxfw/netxfw/internal/app"

ver := app.Version()

// ✅ 新代码
import "github.com/netxfw/netxfw/internal/version"

ver := version.Version
```

## 迁移工具

### 自动化迁移脚本

创建 `scripts/migrate_api.sh`:

```bash
#!/bin/bash

# 迁移 app.GetAttachedInterfaceInfos
find . -name "*.go" -not -path "./vendor/*" -exec sed -i 's/app\.GetAttachedInterfaceInfos()/xdputil.GetAttachedInterfaceInfos(app.GetPinPath())/g' {} \;

# 迁移 app.LogInfo
find . -name "*.go" -not -path "./vendor/*" -exec sed -i 's/app\.LogInfo(ctx, /logger.Get(ctx).Infof(/g' {} \;

# 迁移 app.Version
find . -name "*.go" -not -path "./vendor/*" -exec sed -i 's/app\.Version()/version.Version/g' {} \;

echo "Migration complete. Please review changes and run tests."
```

### CI 检查

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
          echo "Checking for deprecated API usage..."
          
          # 检查 app.GetAttachedInterfaceInfos
          if grep -r "app\.GetAttachedInterfaceInfos" --include="*.go" | grep -v "ops_util.go" | grep -v "_test.go"; then
            echo "❌ Error: Found usage of deprecated function app.GetAttachedInterfaceInfos()"
            echo "Please use xdputil.GetAttachedInterfaceInfos() instead."
            exit 1
          fi
          
          # 检查 app.LogInfo
          if grep -r "app\.LogInfo" --include="*.go" | grep -v "ops_util.go" | grep -v "_test.go"; then
            echo "❌ Error: Found usage of deprecated function app.LogInfo()"
            echo "Please use logger.Get(ctx).Infof() instead."
            exit 1
          fi
          
          # 检查 app.Version
          if grep -r "app\.Version()" --include="*.go" | grep -v "ops_util.go" | grep -v "_test.go"; then
            echo "❌ Error: Found usage of deprecated function app.Version()"
            echo "Please use version.Version instead."
            exit 1
          fi
          
          echo "✅ No deprecated API usage found"
```

## 迁移最佳实践

### 1. 逐步迁移

不要一次性迁移所有代码，而是：

1. **识别使用位置**：使用 `grep` 找到所有使用废弃函数的地方
2. **优先级排序**：从最简单的迁移开始
3. **逐个迁移**：一次迁移一个文件或模块
4. **运行测试**：每次迁移后运行测试确保正确性

### 2. 保持兼容性

在迁移期间，保持新旧 API 的兼容性：

```go
// 旧代码仍然可以工作（但会显示废弃警告）
infos, err := app.GetAttachedInterfaceInfos()

// 新代码推荐使用
infos, err := xdputil.GetAttachedInterfaceInfos(app.GetPinPath())
```

### 3. 更新文档

迁移完成后，更新相关文档：

- API 文档
- 示例代码
- 教程和指南

### 4. 通知用户

通过以下方式通知用户：

- CHANGELOG.md 中记录废弃信息
- GitHub Release Notes 中说明
- 文档中标记废弃函数

## 废弃策略

### 版本规划

| 版本 | 状态 | 说明 |
|------|------|------|
| v2.0 | ✅ 当前 | 旧 API 正常使用 |
| v2.1 | ⚠️ 废弃警告 | 标记为废弃，显示警告 |
| v2.2-2.9 | ⚠️ 废弃警告 | 持续警告，鼓励迁移 |
| v3.0 | 🔴 移除 | 旧 API 被移除 |

### 废弃时间表

- **标记废弃**: 功能发布后立即标记
- **警告期**: 至少 2 个次要版本（约 6 个月）
- **移除**: 主版本升级时移除

## 常见问题

### Q: 为什么要废弃这些函数？

A: 这些函数的职责不够清晰，应该移至更合适的包中。这有助于：
- 提高代码组织性
- 降低耦合度
- 提高可维护性

### Q: 旧代码会立即失效吗？

A: 不会。旧代码会在至少 2 个次要版本中继续工作，只是会显示废弃警告。

### Q: 如何处理大量使用旧 API 的代码？

A: 使用自动化迁移脚本，或者逐步迁移。建议优先迁移新代码，旧代码可以延后。

### Q: 如果迁移后出现问题怎么办？

A: 可以回滚到旧 API，或者提交 Issue 寻求帮助。

## 相关文档

- [应用服务层重构计划](./10-02_app_layer_refactoring.md)
- [版本兼容性策略](./version-compatibility.md)
- [CHANGELOG](../CHANGELOG.md)
