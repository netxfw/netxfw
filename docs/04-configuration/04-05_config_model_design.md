# 配置模型设计说明

## 概述

NetXFW 项目中存在两个配置模型：
- `internal/domain/config.Config` - 领域层配置
- `pkg/sdk.GlobalConfig` - SDK 层配置

这种双重定义是**有意为之的设计决策**，而非设计缺陷。

## 设计理由

### 1. 关注点分离

**领域层配置** (`domainconfig.Config`):
- 包含验证逻辑和业务规则
- 与领域模型紧密耦合
- 可以独立演化，不受外部 API 变化的影响
- 位置：`internal/domain/config/`

**SDK 层配置** (`sdk.GlobalConfig`):
- 用于外部 API 和用户交互
- 保持向后兼容性
- 简化的视图，隐藏内部复杂性
- 位置：`pkg/sdk/`

### 2. 架构边界

```
┌─────────────────────────────────────────────────────────────┐
│                    外部世界 (CLI, API)                        │
│                     使用 sdk.GlobalConfig                    │
└─────────────────────────────────────────────────────────────┘
                            │
                            │ ConfigFromSDK / ConfigToSDK
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                      领域层 (Domain)                         │
│                  使用 domainconfig.Config                    │
│  - 验证逻辑                                                  │
│  - 业务规则                                                  │
│  - 领域模型                                                  │
└─────────────────────────────────────────────────────────────┘
```

### 3. 演化独立性

- **领域层变更**：可以在不影响 SDK API 的情况下修改内部配置结构
- **SDK 层变更**：可以在保持向后兼容性的情况下调整外部 API

## 转换层

转换逻辑位于 `internal/ports/sdk_compat.go`，提供：
- `ConfigFromSDK()` - SDK 配置 → 领域配置
- `ConfigToSDK()` - 领域配置 → SDK 配置

### 使用统计

- 15 个文件中使用
- 60 次调用
- 266 行转换代码

## 优化建议

### 短期优化（已实现）

1. ✅ 转换逻辑已从领域层移至边界层 (`internal/ports/`)
2. ✅ 使用类型别名简化简单转换
3. ✅ 提供辅助函数减少重复代码

### 长期优化（可选）

1. **代码生成**
   ```bash
   # 使用 go generate 自动生成转换代码
   go generate ./internal/ports/
   ```
   - 减少手动维护
   - 确保字段同步

2. **泛型辅助函数**
   ```go
   // 通用切片转换
   func ConvertSlice[T, U any](items []T, conv func(T) U) []U
   
   // 通用映射转换
   func ConvertMap[K comparable, T, U any](items map[K]T, conv func(T) U) map[K]U
   ```

3. **反射优化**
   ```go
   // 使用反射自动转换相同字段
   func AutoConvert(src, dst interface{}) error
   ```

## 最佳实践

### 添加新配置字段

1. 在 `internal/domain/config/config.go` 添加字段（包含验证逻辑）
2. 在 `pkg/sdk/types.go` 添加对应字段（保持向后兼容）
3. 在 `internal/ports/sdk_compat.go` 更新转换函数
4. 添加单元测试验证转换正确性

### 示例

```go
// 1. 领域层配置
type Config struct {
    NewField string `toml:"new_field" validate:"required"`
}

// 2. SDK 层配置
type GlobalConfig struct {
    NewField string `toml:"new_field"`
}

// 3. 转换函数
func ConfigFromSDK(cfg *sdk.GlobalConfig) *domainconfig.Config {
    return &domainconfig.Config{
        NewField: cfg.NewField,
        // ... 其他字段
    }
}

// 4. 测试
func TestConfigConversion(t *testing.T) {
    sdkCfg := &sdk.GlobalConfig{NewField: "test"}
    domainCfg := ConfigFromSDK(sdkCfg)
    assert.Equal(t, "test", domainCfg.NewField)
}
```

## 结论

配置模型的双重定义是一个**合理的架构决策**，它：
- ✅ 保持了领域层的独立性
- ✅ 提供了清晰的架构边界
- ✅ 允许独立演化
- ✅ 保持了 SDK 的向后兼容性

虽然需要维护额外的转换代码，但这是为了获得更好的架构设计而付出的合理代价。

---

**相关文件**：
- [internal/domain/config/config.go](../internal/domain/config/config.go) - 领域层配置
- [pkg/sdk/types.go](../pkg/sdk/types.go) - SDK 层配置
- [internal/ports/sdk_compat.go](../internal/ports/sdk_compat.go) - 转换层
