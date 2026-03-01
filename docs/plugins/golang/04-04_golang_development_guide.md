# Go插件开发指南

## 概述

netxfw 支持通过 Go Plugin 机制扩展功能。Go插件主要用于控制平面的扩展，如API中间件、规则处理器、监控钩子等。Go插件提供比XDP插件更高的灵活性，可以访问完整的Go标准库。

## 环境要求

- Go 1.18+
- Go modules 支持
- 编译时与主程序使用相同版本的 Go

## 插件接口定义

Go插件必须实现特定的接口才能被 netxfw 识别和加载。主要接口包括：

### 1. RuleProcessor 接口

用于扩展规则处理逻辑：

```go
type RuleProcessor interface {
    Process(rule Rule) error
    Validate(rule Rule) error
    Name() string
}
```

### 2. APIMiddleware 接口

用于扩展API功能：

```go
type APIMiddleware interface {
    Handler(next http.HandlerFunc) http.HandlerFunc
    Priority() int  // 数字越小，优先级越高
}
```

### 3. MonitorHook 接口

用于监控和告警：

```go
type MonitorHook interface {
    OnEvent(event Event) error
    EventType() string
}
```

## 快速开始

### 1. 创建插件项目

创建一个新的Go项目作为插件：

```bash
mkdir -p ~/my-netxfw-plugin
cd ~/my-netxfw-plugin
go mod init my-netxfw-plugin
```

### 2. 实现插件接口

创建 `main.go` 文件：

```go
package main

import (
    "encoding/json"
    "fmt"
    "log"
    "net/http"
    "time"
    
    "netxfw/types"  // 假设这是 netxfw 的类型包
)

// 实现规则处理器
type MyRuleProcessor struct{}

func (p *MyRuleProcessor) Name() string {
    return "my-rule-processor"
}

func (p *MyRuleProcessor) Validate(rule types.Rule) error {
    // 自定义验证逻辑
    if rule.IP == "0.0.0.0" {
        return fmt.Errorf("invalid IP: 0.0.0.0")
    }
    return nil
}

func (p *MyRuleProcessor) Process(rule types.Rule) error {
    log.Printf("Processing rule: %+v", rule)
    
    // 自定义处理逻辑
    // 例如：记录到外部系统、发送通知等
    return nil
}

// 实现API中间件
type MyAPIMiddleware struct{}

func (m *MyAPIMiddleware) Priority() int {
    return 10
}

func (m *MyAPIMiddleware) Handler(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        start := time.Now()
        
        log.Printf("Request received: %s %s", r.Method, r.URL.Path)
        
        // 调用下一个处理器
        next(w, r)
        
        log.Printf("Request completed in %v", time.Since(start))
    }
}

// 实现监控钩子
type MyMonitorHook struct{}

func (h *MyMonitorHook) EventType() string {
    return "rule_change"  // 监听规则变更事件
}

func (h *MyMonitorHook) OnEvent(event types.Event) error {
    eventData, _ := json.MarshalIndent(event, "", "  ")
    log.Printf("Rule change event: %s", eventData)
    
    // 可以在这里发送告警、记录到外部系统等
    return nil
}

// 导出插件实例
var (
    RuleProcessorInstance RuleProcessor = &MyRuleProcessor{}
    APIMiddlewareInstance APIMiddleware = &MyAPIMiddleware{}
    MonitorHookInstance   MonitorHook   = &MyMonitorHook{}
)
```

### 3. 编译插件

编译为 `.so` 文件：

```bash
go build -buildmode=plugin -o my_plugin.so
```

## 插件类型详解

### 1. 规则处理器 (RuleProcessor)

用于扩展规则验证和处理逻辑：

```go
type RuleProcessor interface {
    Process(rule Rule) error      // 处理规则
    Validate(rule Rule) error     // 验证规则
    Name() string                // 插件名称
}
```

典型应用场景：
- 验证规则是否符合特定策略
- 将规则同步到外部系统
- 记录规则操作日志

### 2. API中间件 (APIMiddleware)

用于扩展API功能：

```go
type APIMiddleware interface {
    Handler(next http.HandlerFunc) http.HandlerFunc
    Priority() int
}
```

典型应用场景：
- 认证和授权
- 请求日志记录
- 速率限制
- 请求/响应修改

### 3. 监控钩子 (MonitorHook)

用于监控系统事件：

```go
type MonitorHook interface {
    OnEvent(event Event) error
    EventType() string
}
```

典型应用场景：
- 事件告警
- 指标收集
- 审计日志

## 高级功能

### 1. 配置管理

插件可以有自己的配置文件：

```go
type ConfigurablePlugin interface {
    LoadConfig(configPath string) error
    GetConfig() interface{}
}
```

### 2. 状态管理

插件可以维护自己的状态：

```go
type StatefulPlugin interface {
    Init() error
    Cleanup() error
}
```

### 3. 与其他插件通信

使用共享的事件总线：

```go
type EventBus interface {
    Subscribe(topic string, handler EventHandler)
    Publish(topic string, data interface{})
}
```

## 插件加载

### 1. 配置文件方式

在 netxfw 配置文件中指定插件路径：

```yaml
plugins:
  go:
    - path: /path/to/my_plugin.so
      enabled: true
      config:
        param1: value1
        param2: value2
```

### 2. 命令行方式

通过命令行参数加载插件：

```bash
./netxfw daemon --plugin-dir=/path/to/plugins
```

## 最佳实践

### 1. 错误处理
- 插件错误不应影响主程序运行
- 实现优雅降级机制
- 记录详细错误日志

### 2. 性能考虑
- 避免在关键路径上执行耗时操作
- 使用缓存减少重复计算
- 合理使用并发

### 3. 安全性
- 验证所有外部输入
- 避免执行任意代码
- 实现适当的访问控制

### 4. 测试
- 为插件编写单元测试
- 进行集成测试
- 验证错误处理逻辑

## 调试技巧

### 1. 日志记录
使用结构化日志记录插件活动：

```go
log.Printf("[PLUGIN: %s] Action: %s, Result: %v", pluginName, action, result)
```

### 2. 配置验证
在插件初始化时验证配置：

```go
func (p *MyPlugin) Init() error {
    if p.config.Param1 == "" {
        return fmt.Errorf("param1 is required")
    }
    return nil
}
```

## 限制与注意事项

1. **版本兼容性**: 插件必须与主程序使用相同版本的 Go 编译
2. **平台限制**: Go插件不支持交叉编译
3. **生命周期**: 插件无法在运行时卸载
4. **依赖管理**: 插件的依赖版本需与主程序兼容

## 示例插件

可以参考 `internal/plugins/` 目录中的示例实现。

## 故障排除

- **插件无法加载**: 检查 Go 版本兼容性
- **接口不匹配**: 确保实现了正确的接口方法
- **性能问题**: 检查插件中的阻塞操作
- **内存泄漏**: 确保正确实现 Cleanup 方法