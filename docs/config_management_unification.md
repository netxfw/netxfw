# 统一配置管理模块 (Unified Configuration Management Module)

## 概述 (Overview)

为了解决配置管理逻辑分散的问题，我们创建了一个统一的配置管理模块，该模块将所有配置相关的操作集中在一个地方处理。

## 设计目标 (Design Goals)

1. **集中化管理** - 将所有配置加载、保存和访问逻辑集中到一个管理器中
2. **线程安全** - 使用读写锁保护并发访问
3. **向后兼容** - 保持现有API不变，但使用新的管理器
4. **易于维护** - 提供清晰的接口和文档

## 核心组件 (Core Components)

### 1. ConfigManager 结构体
```go
type ConfigManager struct {
    configPath string
    mutex      sync.RWMutex
    config     *types.GlobalConfig
}
```

### 2. Configurable 接口
定义了配置管理的统一接口，便于测试和扩展。

### 3. 单例模式
通过 `GetConfigManager()` 函数提供单例访问。

## 主要功能 (Key Features)

### 配置加载与保存
- `LoadConfig()` - 从文件加载配置
- `SaveConfig()` - 将配置保存到文件
- `UpdateConfig()` - 更新当前配置

### 类型安全的访问器
为每个配置部分提供了专门的 getter 和 setter：
- `GetBaseConfig()` / `SetBaseConfig()`
- `GetWebConfig()` / `SetWebConfig()`
- `GetMetricsConfig()` / `SetMetricsConfig()`
- 等等...

### 并发安全
使用读写锁确保多协程环境下的安全访问。

## 使用方法 (Usage)

### 获取配置管理器
```go
cfgManager := config.GetConfigManager()
```

### 加载配置
```go
err := cfgManager.LoadConfig()
if err != nil {
    // 处理错误
}
```

### 访问配置
```go
cfg := cfgManager.GetConfig()
baseCfg := cfgManager.GetBaseConfig()
```

### 更新配置
```go
newBaseCfg := types.BaseConfig{...}
cfgManager.SetBaseConfig(newBaseCfg)
err := cfgManager.SaveConfig()  // 保存到文件
```

## 更新的文件 (Updated Files)

以下文件已更新以使用新的配置管理器：

1. `/internal/api/server.go` - API服务器配置加载
2. `/internal/api/handlers.go` - API处理器配置访问
3. `/internal/api/auth.go` - 认证中间件配置访问
4. `/internal/app/ops.go` - 操作命令配置访问
5. `/internal/daemon/dp.go` - 数据平面配置访问
6. `/internal/daemon/agent.go` - 控制平面配置访问
7. `/internal/core/sync.go` - 同步模块配置访问

## 优势 (Benefits)

1. **一致性** - 所有配置访问都通过统一接口
2. **安全性** - 线程安全的并发访问
3. **可维护性** - 集中的配置逻辑更容易修改和调试
4. **可测试性** - 明确的接口便于单元测试
5. **性能** - 减少重复的配置加载操作

## 未来扩展 (Future Extensions)

- 添加配置变更通知机制
- 实现配置热重载
- 添加配置验证钩子
- 支持远程配置源