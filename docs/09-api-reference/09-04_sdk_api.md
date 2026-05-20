# NetXFW SDK API 参考文档

**版本**: v2.0  
**最后更新**: 2026-04-19  
**语言**: Go

---

## 📋 目录

1. [概述](#1-概述)
2. [快速开始](#2-快速开始)
3. [API 参考](#3-api-参考)
   - [Blacklist API](#31-blacklist-api)
   - [Whitelist API](#32-whitelist-api)
   - [Rule API](#33-rule-api)
   - [Stats API](#34-stats-api)
   - [Security API](#35-security-api)
   - [Sync API](#36-sync-api)
   - [Conntrack API](#37-conntrack-api)
   - [EventBus](#38-eventbus)
   - [KVStore](#39-kvstore)
4. [示例代码](#4-示例代码)
5. [最佳实践](#5-最佳实践)

---

## 1. 概述

### 1.1 SDK 简介

NetXFW SDK 提供了一个结构化的高级 API，用于与 NetXFW 防火墙进行交互。它封装了底层的 BPF Map 操作，提供了更安全、更易用的接口。

### 1.2 核心组件

```go
type SDK struct {
    Blacklist BlacklistAPI    // 黑名单管理
    Whitelist WhitelistAPI    // 白名单管理
    Rule      RuleAPI         // 规则管理
    Stats     StatsAPI        // 统计信息
    Security  SecurityAPI     // 安全操作
    Sync      SyncAPI         // 同步操作
    Conntrack ConntrackAPI    // 连接跟踪
    EventBus  EventBus        // 事件总线
    Store     KVStore         // 键值存储
}
```

### 1.3 使用场景

- **插件开发**: 编写自定义插件时需要使用 SDK
- **自动化运维**: 通过脚本自动管理防火墙规则
- **监控系统**: 收集防火墙统计信息和状态
- **安全审计**: 检查和管理防火墙规则

---

## 2. 快速开始

### 2.1 初始化 SDK

```go
package main

import (
    "github.com/netxfw/netxfw/pkg/sdk"
)

func main() {
    // 创建管理器（通常由框架提供）
    mgr := getManager() // 实现 ManagerInterface 的对象
    
    // 创建 SDK 实例
    sdk := sdk.NewSDK(mgr)
    
    // 现在可以使用 SDK 的各种 API
    // ...
}
```

### 2.2 添加黑名单规则

```go
// 添加单个 IP 到黑名单
err := sdk.Blacklist.Add("192.168.1.100")
if err != nil {
    log.Printf("添加黑名单失败：%v", err)
}

// 添加 IP 段到黑名单
err = sdk.Blacklist.AddCIDR("10.0.0.0/8")
if err != nil {
    log.Printf("添加黑名单网段失败：%v", err)
}

// 添加带端口的黑名单规则
err = sdk.Blacklist.AddPort("192.168.1.100", 22, "tcp")
if err != nil {
    log.Printf("添加端口黑名单失败：%v", err)
}
```

### 2.3 查询统计信息

```go
// 获取所有统计信息
stats := sdk.Stats.GetStats()
fmt.Printf("总数据包：%d\n", stats.TotalPackets)
fmt.Printf("总字节数：%d\n", stats.TotalBytes)
fmt.Printf("丢弃数据包：%d\n", stats.DroppedPackets)

// 获取特定 IP 的统计
ipStats := sdk.Stats.GetIPStats("192.168.1.100")
fmt.Printf("IP 统计：%+v\n", ipStats)
```

---

## 3. API 参考

### 3.1 Blacklist API

黑名单管理 API，用于阻止特定 IP 或 IP 段的访问。

#### 方法定义

```go
type BlacklistAPI interface {
    // Add 添加单个 IP 到黑名单
    Add(ip string) error
    
    // AddCIDR 添加 IP 段到黑名单
    AddCIDR(cidr string) error
    
    // AddPort 添加带端口的黑名单规则
    AddPort(ip string, port int, protocol string) error
    
    // Remove 从黑名单移除 IP
    Remove(ip string) error
    
    // RemoveCIDR 从黑名单移除 IP 段
    RemoveCIDR(cidr string) error
    
    // List 列出所有黑名单规则
    List() ([]IPPortRule, error)
    
    // Clear 清空所有黑名单规则
    Clear() error
    
    // Contains 检查 IP 是否在黑名单中
    Contains(ip string) (bool, error)
}
```

#### 使用示例

```go
// 添加黑名单
sdk.Blacklist.Add("192.168.1.100")

// 添加网段
sdk.Blacklist.AddCIDR("10.0.0.0/8")

// 添加端口规则（阻止 SSH）
sdk.Blacklist.AddPort("192.168.1.100", 22, "tcp")

// 列出所有规则
rules, err := sdk.Blacklist.List()
if err != nil {
    log.Fatal(err)
}
for _, rule := range rules {
    fmt.Printf("黑名单：%s:%d (%s)\n", rule.IP, rule.Port, rule.Protocol)
}

// 检查是否在黑名单中
if inList, _ := sdk.Blacklist.Contains("192.168.1.100"); inList {
    fmt.Println("IP 在黑名单中")
}

// 移除规则
sdk.Blacklist.Remove("192.168.1.100")

// 清空所有
sdk.Blacklist.Clear()
```

#### 参数说明

| 参数 | 类型 | 说明 | 示例 |
|------|------|------|------|
| ip | string | IPv4 或 IPv6 地址 | `192.168.1.100` |
| cidr | string | CIDR 格式的 IP 段 | `10.0.0.0/8` |
| port | int | 端口号 (1-65535) | `22` |
| protocol | string | 协议类型 | `tcp`, `udp` |

#### 错误处理

```go
err := sdk.Blacklist.Add("invalid-ip")
if err != nil {
    // 可能的错误：
    // - invalid IP address format
    // - port out of range
    // - invalid protocol
    log.Printf("错误：%v", err)
}
```

---

### 3.2 Whitelist API

白名单管理 API，用于允许特定 IP 或 IP 段的访问（优先级高于黑名单）。

#### 方法定义

```go
type WhitelistAPI interface {
    // Add 添加单个 IP 到白名单
    Add(ip string) error
    
    // AddCIDR 添加 IP 段到白名单
    AddCIDR(cidr string) error
    
    // AddPort 添加带端口的白名单规则
    AddPort(ip string, port int, protocol string) error
    
    // Remove 从白名单移除 IP
    Remove(ip string) error
    
    // RemoveCIDR 从白名单移除 IP 段
    RemoveCIDR(cidr string) error
    
    // List 列出所有白名单规则
    List() ([]IPPortRule, error)
    
    // Clear 清空所有白名单规则
    Clear() error
    
    // Contains 检查 IP 是否在白名单中
    Contains(ip string) (bool, error)
}
```

#### 使用示例

```go
// 添加信任的 IP
sdk.Whitelist.Add("192.168.1.1")

// 添加信任的网段（内网）
sdk.Whitelist.AddCIDR("192.168.0.0/16")

// 允许特定端口（管理端口）
sdk.Whitelist.AddPort("10.0.0.1", 443, "tcp")

// 白名单优先级高于黑名单
// 即使 IP 在黑名单中，如果在白名单中也会被放行
```

---

### 3.3 Rule API

规则管理 API，用于管理综合的防火墙规则（支持更复杂的匹配条件）。

#### 方法定义

```go
type RuleAPI interface {
    // Add 添加规则
    Add(rule RuleConfig) error
    
    // Remove 移除规则
    Remove(id string) error
    
    // List 列出所有规则
    List() ([]RuleConfig, error)
    
    // Get 获取单个规则
    Get(id string) (*RuleConfig, error)
    
    // Update 更新规则
    Update(id string, rule RuleConfig) error
    
    // Clear 清空所有规则
    Clear() error
}
```

#### RuleConfig 结构

```go
type RuleConfig struct {
    ID          string   // 规则 ID（唯一标识）
    Name        string   // 规则名称
    Description string   // 规则描述
    Enabled     bool     // 是否启用
    Priority    int      // 优先级（数字越小优先级越高）
    
    // 匹配条件
    SourceIP    string   // 源 IP/CIDR
    DestIP      string   // 目标 IP/CIDR
    SourcePort  string   // 源端口（范围：80-90）
    DestPort    string   // 目标端口
    Protocol    string   // 协议：tcp/udp/icmp/any
    
    // 动作
    Action      string   // allow/deny/limit/log
    Limit       *LimitConfig // 限速配置（当 Action=limit 时）
    
    // 日志
    Log         bool     // 是否记录日志
    LogPrefix   string   // 日志前缀
}

type LimitConfig struct {
    Rate    int // 速率（包/秒）
    Burst   int // 突发量
}
```

#### 使用示例

```go
// 添加允许规则
rule := sdk.RuleConfig{
    ID:       "allow-ssh",
    Name:     "允许 SSH 访问",
    Enabled:  true,
    Priority: 10,
    DestPort: "22",
    Protocol: "tcp",
    Action:   "allow",
}
err := sdk.Rule.Add(rule)

// 添加限速规则
limitRule := sdk.RuleConfig{
    ID:       "limit-http",
    Name:     "HTTP 限速",
    Enabled:  true,
    Priority: 20,
    DestPort: "80",
    Protocol: "tcp",
    Action:   "limit",
    Limit: &sdk.LimitConfig{
        Rate:  1000, // 1000 包/秒
        Burst: 5000, // 突发 5000 包
    },
}
err = sdk.Rule.Add(limitRule)

// 更新规则
rule.Enabled = false
err = sdk.Rule.Update("allow-ssh", rule)

// 移除规则
err = sdk.Rule.Remove("allow-ssh")
```

---

### 3.4 Stats API

统计信息 API，用于获取防火墙的性能指标和流量统计。

#### 方法定义

```go
type StatsAPI interface {
    // GetStats 获取全局统计信息
    GetStats() *GlobalStats
    
    // GetIPStats 获取特定 IP 的统计
    GetIPStats(ip string) *IPStats
    
    // GetCPUStats 获取 per-CPU 统计
    GetCPUStats() []CPUStats
    
    // ResetStats 重置统计信息
    ResetStats() error
    
    // GetTopTalkers 获取流量最大的 IP
    GetTopTalkers(limit int) []IPStats
}
```

#### 统计结构

```go
type GlobalStats struct {
    TotalPackets    uint64    // 总数据包数
    TotalBytes      uint64    // 总字节数
    DroppedPackets  uint64    // 丢弃的数据包
    PassedPackets   uint64    // 放行的数据包
    LimitedPackets  uint64    // 限速的数据包
    LastUpdated     time.Time // 最后更新时间
}

type IPStats struct {
    IP            string    // IP 地址
    Packets       uint64    // 数据包数
    Bytes         uint64    // 字节数
    Dropped       uint64    // 丢弃数
    FirstSeen     time.Time // 首次看到时间
    LastSeen      time.Time // 最后看到时间
}

type CPUStats struct {
    CPU           int       // CPU 核心
    Packets       uint64    // 处理的数据包
    DropReasons   map[uint32]uint64 // 丢弃原因统计
}
```

#### 使用示例

```go
// 获取全局统计
stats := sdk.Stats.GetStats()
fmt.Printf("总流量：%d 包，%d 字节\n", stats.TotalPackets, stats.TotalBytes)
fmt.Printf("丢弃率：%.2f%%\n", 
    float64(stats.DroppedPackets)/float64(stats.TotalPackets)*100)

// 获取 Top 10 流量 IP
topTalkers := sdk.Stats.GetTopTalkers(10)
for i, ipStats := range topTalkers {
    fmt.Printf("%d. %s: %d 包\n", i+1, ipStats.IP, ipStats.Packets)
}

// 重置统计
err := sdk.Stats.ResetStats()
```

---

### 3.5 Security API

安全操作 API，用于执行安全相关的管理操作。

#### 方法定义

```go
type SecurityAPI interface {
    // Lock 锁定防火墙（阻止所有流量）
    Lock() error
    
    // Unlock 解锁防火墙（恢复正常运行）
    Unlock() error
    
    // IsLocked 检查是否已锁定
    IsLocked() (bool, error)
    
    // EmergencyAllow 紧急允许特定 IP（即使在全局锁定时）
    EmergencyAllow(ip string) error
    
    // GetSecurityConfig 获取安全配置
    GetSecurityConfig() *SecurityConfig
    
    // UpdateSecurityConfig 更新安全配置
    UpdateSecurityConfig(cfg *SecurityConfig) error
}
```

#### SecurityConfig 结构

```go
type SecurityConfig struct {
    AutoLock      bool   // 自动锁定（检测到攻击时）
    LockThreshold int    // 触发锁定的阈值（包/秒）
    LockDuration  int    // 锁定时长（秒）
    AlertEnabled  bool   // 启用告警
    AlertEmail    string // 告警邮箱
}
```

#### 使用示例

```go
// 紧急锁定（维护模式）
err := sdk.Security.Lock()

// 紧急允许管理员 IP
err = sdk.Security.EmergencyAllow("192.168.1.1")

// 检查锁定状态
if locked, _ := sdk.Security.IsLocked(); locked {
    fmt.Println("防火墙已锁定")
}

// 解锁
err = sdk.Security.Unlock()

// 配置自动锁定
cfg := &sdk.SecurityConfig{
    AutoLock:      true,
    LockThreshold: 100000, // 10 万包/秒
    LockDuration:  300,    // 5 分钟
    AlertEnabled:  true,
    AlertEmail:    "admin@example.com",
}
err = sdk.Security.UpdateSecurityConfig(cfg)
```

---

### 3.6 Sync API

同步操作 API，用于配置同步和持久化。

#### 方法定义

```go
type SyncAPI interface {
    // Map2File 将内存中的配置同步到文件
    Map2File() error
    
    // File2Map 从文件加载配置到内存
    File2Map() error
    
    // AutoSync 启用自动同步
    AutoSync(enabled bool, interval time.Duration)
    
    // GetSyncStatus 获取同步状态
    GetSyncStatus() *SyncStatus
}
```

#### SyncStatus 结构

```go
type SyncStatus struct {
    LastSyncTime   time.Time // 最后同步时间
    SyncEnabled    bool      // 是否启用自动同步
    SyncInterval   time.Duration // 同步间隔
    ConfigFile     string    // 配置文件路径
    IsDirty        bool      // 是否有未同步的更改
}
```

#### 使用示例

```go
// 手动同步到文件
err := sdk.Sync.Map2File()

// 从文件加载
err = sdk.Sync.File2Map()

// 启用自动同步（每 30 秒）
sdk.Sync.AutoSync(true, 30*time.Second)

// 检查同步状态
status := sdk.Sync.GetSyncStatus()
if status.IsDirty {
    fmt.Println("有未同步的更改")
}
```

---

### 3.7 Conntrack API

连接跟踪 API，用于管理活动连接。

#### 方法定义

```go
type ConntrackAPI interface {
    // List 列出所有活动连接
    List() ([]Connection, error)
    
    // Remove 移除特定连接
    Remove(conn ConnectionKey) error
    
    // RemoveByIP 移除特定 IP 的所有连接
    RemoveByIP(ip string) error
    
    // Count 获取连接数
    Count() int
    
    // GetConfig 获取连接跟踪配置
    GetConfig() *ConntrackConfig
    
    // UpdateConfig 更新连接跟踪配置
    UpdateConfig(cfg *ConntrackConfig) error
}
```

#### Connection 结构

```go
type Connection struct {
    SrcIP       string    // 源 IP
    SrcPort     int       // 源端口
    DstIP       string    // 目标 IP
    DstPort     int       // 目标端口
    Protocol    string    // 协议
    State       string    // 连接状态
    StartTime   time.Time // 开始时间
    LastSeen    time.Time // 最后活动时间
    Packets     uint64    // 数据包数
    Bytes       uint64    // 字节数
}
```

#### 使用示例

```go
// 列出所有连接
conns, err := sdk.Conntrack.List()
if err != nil {
    log.Fatal(err)
}
fmt.Printf("活动连接数：%d\n", len(conns))

// 移除特定 IP 的所有连接
err = sdk.Conntrack.RemoveByIP("192.168.1.100")

// 获取连接数
count := sdk.Conntrack.Count()
fmt.Printf("当前连接数：%d\n", count)

// 配置连接跟踪
cfg := &sdk.ConntrackConfig{
    MaxConnections: 100000,
    Timeout:        300 * time.Second,
}
err = sdk.Conntrack.UpdateConfig(cfg)
```

---

### 3.8 EventBus

事件总线，用于订阅和发布防火墙事件。

#### 方法定义

```go
type EventBus interface {
    // Subscribe 订阅事件
    Subscribe(eventType string, handler EventHandler) Subscription
    
    // Publish 发布事件
    Publish(eventType string, data any)
    
    // Unsubscribe 取消订阅
    Unsubscribe(sub Subscription)
}

type EventHandler func(event Event)
type Event struct {
    Type      string
    Timestamp time.Time
    Data      any
}
```

#### 事件类型

```go
const (
    EventRuleAdded    = "rule.added"
    EventRuleRemoved  = "rule.removed"
    EventLockChanged  = "lock.changed"
    EventConfigReload = "config.reload"
    EventAlert        = "alert"
)
```

#### 使用示例

```go
// 订阅规则添加事件
sub := sdk.EventBus.Subscribe(sdk.EventRuleAdded, func(event sdk.Event) {
    rule := event.Data.(*sdk.RuleConfig)
    fmt.Printf("规则已添加：%s\n", rule.Name)
})

// 订阅告警事件
sdk.EventBus.Subscribe(sdk.EventAlert, func(event sdk.Event) {
    alert := event.Data.(*sdk.Alert)
    fmt.Printf("告警：%s - %s\n", alert.Level, alert.Message)
})

// 发布事件（通常在内部使用）
sdk.EventBus.Publish(sdk.EventRuleAdded, &sdk.RuleConfig{
    ID:   "test",
    Name: "测试规则",
})

// 取消订阅
defer sdk.EventBus.Unsubscribe(sub)
```

---

### 3.9 KVStore

键值存储，用于插件间的数据共享。

#### 方法定义

```go
type KVStore interface {
    // Set 存储键值对
    Set(key string, value any)
    
    // Get 获取值
    Get(key string) (any, bool)
    
    // Delete 删除键
    Delete(key string)
    
    // Keys 获取所有键
    Keys() []string
}
```

#### 使用示例

```go
// 存储数据
sdk.Store.Set("counter", 42)
sdk.Store.Set("config", &MyConfig{Key: "value"})

// 获取数据
if val, ok := sdk.Store.Get("counter"); ok {
    counter := val.(int)
    fmt.Printf("计数器：%d\n", counter)
}

// 删除
sdk.Store.Delete("counter")

// 遍历所有键
for _, key := range sdk.Store.Keys() {
    if val, ok := sdk.Store.Get(key); ok {
        fmt.Printf("%s: %v\n", key, val)
    }
}
```

---

## 4. 示例代码

### 4.1 完整的规则管理示例

```go
package main

import (
    "fmt"
    "log"
    "time"
    
    "github.com/netxfw/netxfw/pkg/sdk"
)

func main() {
    // 初始化
    mgr := getManager()
    sdk := sdk.NewSDK(mgr)
    
    // 添加白名单（信任的 IP）
    trustedIPs := []string{
        "192.168.1.1",
        "192.168.1.2",
        "10.0.0.0/8",
    }
    for _, ip := range trustedIPs {
        if err := sdk.Whitelist.Add(ip); err != nil {
            log.Printf("添加白名单失败 %s: %v", ip, err)
        }
    }
    
    // 添加黑名单（恶意 IP）
    blockedIPs := []string{
        "203.0.113.1",
        "198.51.100.0/24",
    }
    for _, ip := range blockedIPs {
        if err := sdk.Blacklist.Add(ip); err != nil {
            log.Printf("添加黑名单失败 %s: %v", ip, err)
        }
    }
    
    // 添加限速规则
    rule := sdk.RuleConfig{
        ID:       "limit-ssh",
        Name:     "SSH 限速",
        Enabled:  true,
        Priority: 100,
        DestPort: "22",
        Protocol: "tcp",
        Action:   "limit",
        Limit: &sdk.LimitConfig{
            Rate:  100,  // 100 包/秒
            Burst: 500,  // 突发 500 包
        },
    }
    if err := sdk.Rule.Add(rule); err != nil {
        log.Fatalf("添加规则失败：%v", err)
    }
    
    // 监控统计
    ticker := time.NewTicker(5 * time.Second)
    defer ticker.Stop()
    
    for range ticker.C {
        stats := sdk.Stats.GetStats()
        fmt.Printf("[%s] 总包数：%d, 丢弃：%d, 放行：%d\n",
            time.Now().Format("15:04:05"),
            stats.TotalPackets,
            stats.DroppedPackets,
            stats.PassedPackets)
        
        // 检查 Top 10 流量 IP
        topTalkers := sdk.Stats.GetTopTalkers(10)
        fmt.Println("Top 10 流量 IP:")
        for i, ts := range topTalkers {
            fmt.Printf("  %d. %s: %d 包\n", i+1, ts.IP, ts.Packets)
        }
    }
}
```

### 4.2 事件监控示例

```go
package main

import (
    "fmt"
    "os"
    "os/signal"
    
    "github.com/netxfw/netxfw/pkg/sdk"
)

func main() {
    mgr := getManager()
    sdk := sdk.NewSDK(mgr)
    
    // 订阅所有事件
    events := []string{
        sdk.EventRuleAdded,
        sdk.EventRuleRemoved,
        sdk.EventLockChanged,
        sdk.EventAlert,
    }
    
    for _, eventType := range events {
        sdk.EventBus.Subscribe(eventType, func(event sdk.Event) {
            fmt.Printf("[%s] 事件：%s\n", event.Timestamp, event.Type)
            fmt.Printf("  数据：%+v\n", event.Data)
        })
    }
    
    // 等待退出信号
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, os.Interrupt)
    <-sigChan
    
    fmt.Println("正在退出...")
}
```

### 4.3 批量操作示例

```go
package main

import (
    "bufio"
    "fmt"
    "os"
    "strings"
    
    "github.com/netxfw/netxfw/pkg/sdk"
)

// 从文件批量导入黑名单
func importBlacklistFromFile(sdk *sdk.SDK, filename string) error {
    file, err := os.Open(filename)
    if err != nil {
        return err
    }
    defer file.Close()
    
    scanner := bufio.NewScanner(file)
    lineNum := 0
    successCount := 0
    errorCount := 0
    
    for scanner.Scan() {
        lineNum++
        ip := strings.TrimSpace(scanner.Text())
        
        // 跳过空行和注释
        if ip == "" || strings.HasPrefix(ip, "#") {
            continue
        }
        
        if err := sdk.Blacklist.Add(ip); err != nil {
            fmt.Printf("第 %d 行失败 [%s]: %v\n", lineNum, ip, err)
            errorCount++
        } else {
            successCount++
        }
    }
    
    fmt.Printf("导入完成：成功 %d, 失败 %d\n", successCount, errorCount)
    return scanner.Err()
}

// 导出黑名单到文件
func exportBlacklistToFile(sdk *sdk.SDK, filename string) error {
    rules, err := sdk.Blacklist.List()
    if err != nil {
        return err
    }
    
    file, err := os.Create(filename)
    if err != nil {
        return err
    }
    defer file.Close()
    
    for _, rule := range rules {
        _, err := fmt.Fprintf(file, "%s\n", rule.IP)
        if err != nil {
            return err
        }
    }
    
    fmt.Printf("导出完成：共 %d 条规则\n", len(rules))
    return nil
}
```

---

## 5. 最佳实践

### 5.1 错误处理

```go
// ✅ 好的做法：详细记录错误
if err := sdk.Blacklist.Add(ip); err != nil {
    log.Printf("添加黑名单失败 [IP=%s]: %v", ip, err)
    // 根据错误类型采取不同措施
    if strings.Contains(err.Error(), "invalid IP") {
        // 跳过无效的 IP
        continue
    }
    // 其他错误可能需要重试或告警
}

// ❌ 不好的做法：忽略错误
sdk.Blacklist.Add(ip) // 不检查错误
```

### 5.2 资源管理

```go
// ✅ 好的做法：及时清理不需要的资源
sub := sdk.EventBus.Subscribe(eventType, handler)
defer sdk.EventBus.Unsubscribe(sub)

// ✅ 好的做法：批量操作后同步
for _, ip := range ips {
    sdk.Blacklist.Add(ip)
}
sdk.Sync.Map2File() // 批量操作后持久化

// ❌ 不好的做法：频繁同步
for _, ip := range ips {
    sdk.Blacklist.Add(ip)
    sdk.Sync.Map2File() // 每次都同步，性能差
}
```

### 5.3 性能优化

```go
// ✅ 好的做法：使用批量接口（如果有）
sdk.Blacklist.BatchAdd(ips)

// ✅ 好的做法：合理设置统计收集频率
ticker := time.NewTicker(10 * time.Second) // 不要太频繁
defer ticker.Stop()

// ✅ 好的做法：限制查询结果数量
topTalkers := sdk.Stats.GetTopTalkers(10) // 只获取 Top 10

// ❌ 不好的做法：过于频繁的统计查询
for {
    sdk.Stats.GetStats() // 每秒查询多次
    time.Sleep(100 * time.Millisecond)
}
```

### 5.4 并发安全

```go
// ✅ 好的做法：SDK 是并发安全的，可以在多个 goroutine 中使用
var wg sync.WaitGroup
for i := 0; i < 10; i++ {
    wg.Add(1)
    go func(id int) {
        defer wg.Done()
        sdk.Blacklist.Add(fmt.Sprintf("192.168.1.%d", id))
    }(i)
}
wg.Wait()

// SDK 内部已处理并发，无需额外加锁
```

### 5.5 日志记录

```go
// ✅ 好的做法：记录关键操作
log.Printf("添加黑名单规则：IP=%s, 原因=%s", ip, reason)

// ✅ 好的做法：使用结构化日志
log.Printf("[SECURITY] 检测到攻击 [IP=%s, 类型=%s, 次数=%d]", 
    ip, attackType, count)

// ❌ 不好的做法：记录敏感信息
log.Printf("Token=%s", secretToken) // 不要记录敏感信息
```

---

## 附录

### A. 错误码说明

| 错误码 | 说明 | 解决方案 |
|--------|------|----------|
| `ErrInvalidIP` | IP 地址格式无效 | 检查 IP 格式 |
| `ErrInvalidPort` | 端口号超出范围 | 使用 1-65535 的端口 |
| `ErrInvalidCIDR` | CIDR 格式错误 | 检查 CIDR 格式 |
| `ErrRuleExists` | 规则已存在 | 先删除或更新现有规则 |
| `ErrRuleNotFound` | 规则不存在 | 检查规则 ID |
| `ErrMapFull` | BPF Map 已满 | 清理旧规则或增加容量 |

### B. 性能建议

- **批量操作**: 尽量批量添加/删除规则，减少 Map 操作次数
- **合理统计**: 统计收集频率建议 5-10 秒一次
- **限制查询**: 使用 List 接口时添加合理的过滤条件
- **事件订阅**: 及时取消不需要的订阅

### C. 相关文档

- [REST API 参考](09-03_api_reference.md)
- [插件开发指南](../06-plugin-development/06-01_plugins.md)
- [配置管理](../04-configuration/04-03_configuration_reference.md)

---

**文档维护**: NetXFW 开发团队  
**问题反馈**: GitHub Issues  
**最后更新**: 2026-04-19
