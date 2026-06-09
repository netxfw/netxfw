# NetXFW 适配器模式（六边形架构）

**版本**: v2.0  
**最后更新**: 2026-04-19  
**状态**: 部分实施（配置适配器和插件适配器已实现，数据平面适配器尚未实现）

---

## 📋 目录

1. [概述](#1-概述)
2. [六边形架构](#2-六边形架构)
3. [适配器实现](#3-适配器实现)
4. [使用指南](#4-使用指南)
5. [最佳实践](#5-最佳实践)

---

## 1. 概述

### 1.1 什么是适配器模式？

适配器模式是六边形架构（Hexagonal Architecture）的核心组成部分，用于：

- **隔离领域层**: 领域模型不依赖外部系统（数据库、HTTP、文件系统等）
- **统一接口**: 为不同的外部系统提供统一的接口
- **易于测试**: 可以轻松替换为 Mock 实现
- **灵活扩展**: 新增外部系统无需修改领域代码

### 1.2 NetXFW 中的适配器

NetXFW 使用适配器模式连接领域层与外部世界：

```
┌─────────────────────────────────────────────────────────────┐
│                    NetXFW 适配器架构                         │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              领域层 (Domain Layer)                   │   │
│  │  • 领域模型 (Rule, Config, Plugin...)               │   │
│  │  • 领域服务                                         │   │
│  │  • 仓库接口 (Repository Interface)                  │   │
│  └─────────────────────────────────────────────────────┘   │
│           ▲                    ▲                            │
│           │ 驱动               │ 被驱动                      │
│           │ (输入)             │ (输出)                      │
│  ┌────────┴────────┐  ┌────────┴────────┐                  │
│  │  输入适配器     │  │   输出适配器    │                  │
│  │  (Driving)      │  │   (Driven)      │                  │
│  │                 │  │                 │                  │
│  │ • CLI 适配器    │  │ • 配置文件适配器 │                  │
│  │ • HTTP 适配器   │  │ • 数据平面适配器 │                  │
│  │ • Web UI 适配器 │  │ • 日志适配器    │                  │
│  │ • 插件适配器   │  │ • 监控适配器    │                  │
│  └─────────────────┘  └─────────────────┘                  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 2. 六边形架构

### 2.1 架构层次

```
┌─────────────────────────────────────────────────────────────┐
│                   用户接口层 (Interfaces)                    │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │   CLI       │  │  REST API   │  │   Web UI    │         │
│  │  Adapter    │  │  Adapter    │  │  Adapter    │         │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘         │
└─────────┼────────────────┼────────────────┼─────────────────┘
          │                │                │
          │ 端口 (Ports)   │                │
          ▼                ▼                ▼
┌─────────────────────────────────────────────────────────────┐
│                    领域层 (Domain)                           │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  • 领域模型 (Rule, Config, Plugin...)               │   │
│  │  • 领域服务                                         │   │
│  │  • 仓库接口                                         │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
          │                │                │
          │ 端口 (Ports)   │                │
          ▼                ▼                ▼
┌─────────────────────────────────────────────────────────────┐
│                基础设施层 (Infrastructure)                   │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │  配置文件   │  │  数据平面   │  │   日志系统  │         │
│  │  Adapter    │  │  Adapter    │  │  Adapter    │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
└─────────────────────────────────────────────────────────────┘
```

### 2.2 端口（Ports）

端口是领域层定义的接口，用于与外部世界交互。

#### 输入端口（Input Ports）

```go
// application/ports/rule_port.go

// RulePort 规则管理端口（输入端口）
type RulePort interface {
    // CreateRule 创建规则
    CreateRule(cmd CreateRuleCommand) (*Rule, error)
    
    // UpdateRule 更新规则
    UpdateRule(id string, cmd UpdateRuleCommand) (*Rule, error)
    
    // DeleteRule 删除规则
    DeleteRule(id string) error
    
    // GetRule 获取规则
    GetRule(id string) (*Rule, error)
    
    // ListRules 列出所有规则
    ListRules(filter RuleFilter) ([]*Rule, error)
}
```

#### 输出端口（Output Ports）

```go
// domain/rule/repository.go

// RuleRepository 规则仓库端口（输出端口）
type RuleRepository interface {
    // Save 保存规则
    Save(rule *Rule) error
    
    // FindByID 根据 ID 查找
    FindByID(id string) (*Rule, error)
    
    // FindAll 查找所有
    FindAll() ([]*Rule, error)
    
    // Delete 删除
    Delete(id string) error
}

// domain/config/persister.go

// ConfigPersister 配置持久化端口（输出端口）
type ConfigPersister interface {
    // Load 加载配置
    Load(path string) (*Config, error)
    
    // Save 保存配置
    Save(cfg *Config, path string) error
    
    // Restore 恢复配置
    Restore(snapshotID string) (*Config, error)
}
```

---

## 3. 适配器实现

### 3.1 配置文件适配器

**位置**: `internal/adapters/configfile/`

**职责**: 实现配置持久化端口，处理配置文件的加载、保存和恢复。

#### 文件结构

```
adapters/configfile/
├── load.go           # 加载配置文件
├── save.go           # 保存配置文件
├── restore.go        # 恢复配置快照
├── snapshot.go       # 快照管理
├── default_template.go # 默认配置模板
└── time.go           # 时间工具
```

#### 加载配置

```go
// adapters/configfile/load.go

package configfile

import (
    "os"
    "path/filepath"
    "github.com/BurntSushi/toml"
    domainconfig "github.com/netxfw/netxfw/internal/domain/config"
)

// Load 从 TOML 文件加载配置
func Load(path string) (*domainconfig.Config, error) {
    // 路径清理（安全）
    safePath := filepath.Clean(path)
    
    // 读取文件
    data, err := os.ReadFile(safePath)
    if err != nil {
        return nil, err
    }
    
    // 创建默认配置
    cfg := domainconfig.DefaultConfig()
    
    // 解码 TOML
    if _, err := toml.Decode(string(data), &cfg); err != nil {
        return nil, err
    }
    
    // 验证配置
    if err := domainconfig.Validate(&cfg); err != nil {
        return nil, fmt.Errorf("configuration validation failed: %w", err)
    }
    
    return &cfg, nil
}

// Encode 将配置编码为 TOML
func Encode(cfg *domainconfig.Config) ([]byte, error) {
    var buf bytes.Buffer
    if err := toml.NewEncoder(&buf).Encode(cfg); err != nil {
        return nil, err
    }
    return buf.Bytes(), nil
}
```

#### 保存配置

```go
// adapters/configfile/save.go

package configfile

import (
    "os"
    "path/filepath"
    "time"
)

// Save 保存配置到文件
func Save(cfg *domainconfig.Config, path string) error {
    // 编码配置
    data, err := Encode(cfg)
    if err != nil {
        return err
    }
    
    // 确保目录存在
    dir := filepath.Dir(path)
    if err := os.MkdirAll(dir, 0755); err != nil {
        return err
    }
    
    // 原子写入（先写临时文件，再重命名）
    tmpPath := path + ".tmp." + fmt.Sprintf("%d", time.Now().UnixNano())
    if err := os.WriteFile(tmpPath, data, 0644); err != nil {
        return err
    }
    
    // 重命名（原子操作）
    if err := os.Rename(tmpPath, path); err != nil {
        return err
    }
    
    return nil
}
```

#### 恢复配置

```go
// adapters/configfile/restore.go

package configfile

import (
    "fmt"
    "os"
    "path/filepath"
)

// Restore 从快照恢复配置
func Restore(snapshotID string) (*domainconfig.Config, error) {
    // 快照文件路径
    snapshotPath := filepath.Join(
        getSnapshotDir(),
        fmt.Sprintf("config-%s.toml", snapshotID),
    )
    
    // 检查快照是否存在
    if _, err := os.Stat(snapshotPath); os.IsNotExist(err) {
        return nil, fmt.Errorf("snapshot not found: %s", snapshotID)
    }
    
    // 加载快照
    return Load(snapshotPath)
}

// CreateSnapshot 创建配置快照
func CreateSnapshot(cfg *domainconfig.Config) (string, error) {
    // 生成快照 ID（时间戳）
    snapshotID := time.Now().Format("20060102-150405")
    
    // 快照文件路径
    snapshotPath := filepath.Join(
        getSnapshotDir(),
        fmt.Sprintf("config-%s.toml", snapshotID),
    )
    
    // 保存快照
    if err := Save(cfg, snapshotPath); err != nil {
        return "", err
    }
    
    return snapshotID, nil
}
```

### 3.2 数据平面适配器（规划中）

> **注意**：此适配器目前处于设计规划阶段，尚未实现。当前数据平面操作通过 `internal/datapath/xdp/backend/` 直接管理。

**职责**: 实现数据平面操作端口，将领域模型转换为 BPF Map 操作。

#### 文件结构

```
adapters/datapath/
├── manager.go        # 数据平面管理器
├── operations.go     # 数据平面操作
└── converter.go      # 模型转换器
```

#### 管理器实现

```go
// adapters/datapath/manager.go

package datapath

import (
    "github.com/netxfw/netxfw/internal/domain/rule"
    "github.com/netxfw/netxfw/internal/datapath/xdp"
)

// Manager 数据平面管理器
type Manager struct {
    xdpMgr *xdp.Manager
}

// NewManager 创建管理器
func NewManager(xdpMgr *xdp.Manager) *Manager {
    return &Manager{xdpMgr: xdpMgr}
}

// SyncRules 同步规则到数据平面
func (m *Manager) SyncRules(rules []*rule.Rule) error {
    // 转换为 BPF Map 操作
    entries, err := convertRulesToMapEntries(rules)
    if err != nil {
        return err
    }
    
    // 批量更新 Map
    return m.xdpMgr.BatchUpdate(entries)
}

// AddRule 添加单个规则
func (m *Manager) AddRule(r *rule.Rule) error {
    entry, err := convertRuleToMapEntry(r)
    if err != nil {
        return err
    }
    return m.xdpMgr.Update(entry)
}

// RemoveRule 移除规则
func (m *Manager) RemoveRule(id string) error {
    return m.xdpMgr.Delete(id)
}
```

#### 模型转换器

```go
// adapters/datapath/converter.go

package datapath

import (
    "github.com/netxfw/netxfw/internal/domain/rule"
    "github.com/netxfw/netxfw/internal/datapath/xdp/maps"
)

// convertRuleToMapEntry 将规则转换为 BPF Map 条目
func convertRuleToMapEntry(r *rule.Rule) (*maps.MapEntry, error) {
    // 协议转换
    proto := convertProtocol(r.Protocol)
    
    // IP 地址转换（支持 IPv4/IPv6）
    srcIP, srcMask := convertIP(r.SourceIP)
    dstIP, dstMask := convertIP(r.DestIP)
    
    // 动作转换
    action := convertAction(r.Action)
    
    // 创建 Map 条目
    return &maps.MapEntry{
        Key: maps.RuleKey{
            ID: hashRule(r),
        },
        Value: maps.RuleValue{
            SourceIP:   srcIP,
            SourceMask: srcMask,
            DestIP:     dstIP,
            DestMask:   dstMask,
            SourcePort: convertPortRange(r.SourcePort),
            DestPort:   convertPortRange(r.DestPort),
            Protocol:   proto,
            Action:     action,
            Priority:   uint32(r.Priority),
        },
    }, nil
}

func convertProtocol(proto rule.Protocol) uint8 {
    switch proto {
    case rule.ProtocolTCP:
        return 6
    case rule.ProtocolUDP:
        return 17
    case rule.ProtocolICMP:
        return 1
    default:
        return 0 // ANY
    }
}

func convertAction(action rule.RuleAction) uint8 {
    switch action {
    case rule.ActionAllow:
        return 0 // XDP_PASS
    case rule.ActionDeny:
        return 1 // XDP_DROP
    case rule.ActionLimit:
        return 2 // XDP_LIMIT
    default:
        return 1 // XDP_DROP
    }
}
```

### 3.3 插件运行时适配器

**位置**: `internal/adapters/plugins/`

**职责**: 实现插件生命周期管理，加载和卸载插件。

#### 文件结构

```
adapters/plugins/
├── runtime/
│   ├── registry.go   # 插件注册表
│   ├── host.go       # 插件宿主
│   └── loader.go     # 插件加载器
```

#### 插件注册表

```go
// adapters/plugins/runtime/registry.go

package runtime

import (
    "sync"
    "github.com/netxfw/netxfw/internal/domain/plugin"
)

// Registry 插件注册表
type Registry struct {
    plugins map[string]*plugin.Instance
    mu      sync.RWMutex
}

// NewRegistry 创建注册表
func NewRegistry() *Registry {
    return &Registry{
        plugins: make(map[string]*plugin.Instance),
    }
}

// Register 注册插件
func (r *Registry) Register(p plugin.Plugin) error {
    r.mu.Lock()
    defer r.mu.Unlock()
    
    name := p.Name()
    
    // 检查是否已注册
    if _, exists := r.plugins[name]; exists {
        return fmt.Errorf("plugin %s already registered", name)
    }
    
    // 创建插件实例
    instance := &plugin.Instance{
        Plugin:  p,
        Status:  plugin.StatusStopped,
        Version: p.Version(),
    }
    
    r.plugins[name] = instance
    return nil
}

// Get 获取插件
func (r *Registry) Get(name string) (*plugin.Instance, error) {
    r.mu.RLock()
    defer r.mu.RUnlock()
    
    instance, exists := r.plugins[name]
    if !exists {
        return nil, fmt.Errorf("plugin %s not found", name)
    }
    
    return instance, nil
}

// List 列出所有插件
func (r *Registry) List() []*plugin.Instance {
    r.mu.RLock()
    defer r.mu.RUnlock()
    
    instances := make([]*plugin.Instance, 0, len(r.plugins))
    for _, instance := range r.plugins {
        instances = append(instances, instance)
    }
    
    return instances
}
```

#### 插件宿主

```go
// adapters/plugins/runtime/host.go

package runtime

import (
    "github.com/netxfw/netxfw/internal/domain/plugin"
)

// Host 插件宿主
type Host struct {
    registry  *Registry
    eventBus  EventBus
    logger    Logger
}

// NewHost 创建宿主
func NewHost(registry *Registry, eventBus EventBus, logger Logger) *Host {
    return &Host{
        registry: registry,
        eventBus: eventBus,
        logger:   logger,
    }
}

// StartPlugin 启动插件
func (h *Host) StartPlugin(name string) error {
    instance, err := h.registry.Get(name)
    if err != nil {
        return err
    }
    
    // 检查状态
    if instance.Status == plugin.StatusRunning {
        return fmt.Errorf("plugin %s is already running", name)
    }
    
    // 初始化插件
    ctx := &plugin.Context{
        Logger:   h.logger,
        EventBus: h.eventBus,
    }
    
    if err := instance.Init(ctx); err != nil {
        return err
    }
    
    // 启动插件
    if err := instance.Start(); err != nil {
        return err
    }
    
    instance.Status = plugin.StatusRunning
    
    // 发布事件
    h.eventBus.Publish("plugin.started", PluginEvent{
        Name: name,
        Time: time.Now(),
    })
    
    h.logger.Info("plugin started", "name", name)
    return nil
}

// StopPlugin 停止插件
func (h *Host) StopPlugin(name string) error {
    instance, err := h.registry.Get(name)
    if err != nil {
        return err
    }
    
    // 检查状态
    if instance.Status == plugin.StatusStopped {
        return fmt.Errorf("plugin %s is already stopped", name)
    }
    
    // 停止插件
    if err := instance.Stop(); err != nil {
        return err
    }
    
    instance.Status = plugin.StatusStopped
    
    // 发布事件
    h.eventBus.Publish("plugin.stopped", PluginEvent{
        Name: name,
        Time: time.Now(),
    })
    
    h.logger.Info("plugin stopped", "name", name)
    return nil
}
```

### 3.4 HTTP API 适配器

**位置**: `internal/api/`

**职责**: 实现 HTTP 输入端口，将 HTTP 请求转换为领域命令。

#### 请求处理

```go
// api/handlers_rules.go

package api

import (
    "encoding/json"
    "net/http"
    
    "github.com/netxfw/netxfw/application/services"
    "github.com/netxfw/netxfw/internal/domain/rule"
)

// RuleHandlers 规则 HTTP 处理器
type RuleHandlers struct {
    ruleService *services.RuleService
}

// CreateRule 创建规则 HTTP 处理器
func (h *RuleHandlers) CreateRule(w http.ResponseWriter, r *http.Request) {
    // 解析请求体
    var req CreateRuleRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    
    // 转换为领域命令
    cmd := services.CreateRuleCommand{
        ID:          req.ID,
        Name:        req.Name,
        Description: req.Description,
        Priority:    req.Priority,
        SourceIP:    parseCIDR(req.SourceIP),
        DestIP:      parseCIDR(req.DestIP),
        SourcePort:  parsePortRange(req.SourcePort),
        DestPort:    parsePortRange(req.DestPort),
        Protocol:    parseProtocol(req.Protocol),
        Action:      parseAction(req.Action),
    }
    
    // 调用领域服务
    createdRule, err := h.ruleService.CreateRule(cmd)
    if err != nil {
        handleDomainError(w, err)
        return
    }
    
    // 返回响应
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusCreated)
    json.NewEncoder(w).Encode(toRuleResponse(createdRule))
}

// ListRules 列出规则 HTTP 处理器
func (h *RuleHandlers) ListRules(w http.ResponseWriter, r *http.Request) {
    // 解析查询参数
    filter := services.RuleFilter{
        Enabled: parseBool(r.URL.Query().Get("enabled")),
        Protocol: r.URL.Query().Get("protocol"),
    }
    
    // 调用领域服务
    rules, err := h.ruleService.ListRules(filter)
    if err != nil {
        handleDomainError(w, err)
        return
    }
    
    // 返回响应
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(toRuleListResponse(rules))
}

// 请求/响应 DTO

type CreateRuleRequest struct {
    ID          string `json:"id"`
    Name        string `json:"name"`
    Description string `json:"description"`
    Priority    int    `json:"priority"`
    SourceIP    string `json:"source_ip"`
    DestIP      string `json:"dest_ip"`
    SourcePort  string `json:"source_port"`
    DestPort    string `json:"dest_port"`
    Protocol    string `json:"protocol"`
    Action      string `json:"action"`
}

type RuleResponse struct {
    ID          string    `json:"id"`
    Name        string    `json:"name"`
    Description string    `json:"description"`
    Enabled     bool      `json:"enabled"`
    Priority    int       `json:"priority"`
    SourceIP    string    `json:"source_ip"`
    DestIP      string    `json:"dest_ip"`
    SourcePort  string    `json:"source_port"`
    DestPort    string    `json:"dest_port"`
    Protocol    string    `json:"protocol"`
    Action      string    `json:"action"`
    CreatedAt   time.Time `json:"created_at"`
    UpdatedAt   time.Time `json:"updated_at"`
}

func toRuleResponse(r *rule.Rule) *RuleResponse {
    return &RuleResponse{
        ID:          r.ID,
        Name:        r.Name,
        Description: r.Description,
        Enabled:     r.Enabled,
        Priority:    r.Priority,
        SourceIP:    formatIP(r.SourceIP),
        DestIP:      formatIP(r.DestIP),
        SourcePort:  formatPortRange(r.SourcePort),
        DestPort:    formatPortRange(r.DestPort),
        Protocol:    formatProtocol(r.Protocol),
        Action:      formatAction(r.Action),
        CreatedAt:   r.CreatedAt,
        UpdatedAt:   r.UpdatedAt,
    }
}
```

---

## 4. 使用指南

### 4.1 如何使用配置文件适配器

```go
package main

import (
    "github.com/netxfw/netxfw/internal/adapters/configfile"
)

func main() {
    // 加载配置
    cfg, err := configfile.Load("config.toml")
    if err != nil {
        log.Fatal(err)
    }
    
    // 修改配置
    cfg.Logging.Level = "debug"
    
    // 保存配置
    if err := configfile.Save(cfg, "config.toml"); err != nil {
        log.Fatal(err)
    }
    
    // 创建快照
    snapshotID, err := configfile.CreateSnapshot(cfg)
    if err != nil {
        log.Fatal(err)
    }
    
    // 恢复快照
    restoredCfg, err := configfile.Restore(snapshotID)
    if err != nil {
        log.Fatal(err)
    }
}
```

### 4.2 如何使用数据平面适配器

```go
package main

import (
    "github.com/netxfw/netxfw/internal/adapters/datapath"
    "github.com/netxfw/netxfw/internal/domain/rule"
)

func main() {
    // 创建管理器
    xdpMgr := createXDPManager()
    dpMgr := datapath.NewManager(xdpMgr)
    
    // 创建规则
    rule := &rule.Rule{
        ID:       "allow-ssh",
        Name:     "允许 SSH",
        Enabled:  true,
        Priority: 10,
        DestPort: rule.PortRange{Start: 22, End: 22},
        Protocol: rule.ProtocolTCP,
        Action:   rule.ActionAllow,
    }
    
    // 同步到数据平面
    if err := dpMgr.AddRule(rule); err != nil {
        log.Fatal(err)
    }
    
    // 批量同步
    rules := []*rule.Rule{rule1, rule2, rule3}
    if err := dpMgr.SyncRules(rules); err != nil {
        log.Fatal(err)
    }
}
```

### 4.3 如何使用插件运行时适配器

```go
package main

import (
    "github.com/netxfw/netxfw/internal/adapters/plugins/runtime"
    "github.com/netxfw/netxfw/plugins/logengine"
)

func main() {
    // 创建注册表
    registry := runtime.NewRegistry()
    
    // 创建宿主
    host := runtime.NewHost(registry, eventBus, logger)
    
    // 注册插件
    logPlugin := logengine.New()
    if err := registry.Register(logPlugin); err != nil {
        log.Fatal(err)
    }
    
    // 启动插件
    if err := host.StartPlugin("logengine"); err != nil {
        log.Fatal(err)
    }
    
    // 列出插件
    instances := registry.List()
    for _, inst := range instances {
        fmt.Printf("插件：%s, 状态：%s, 版本：%s\n",
            inst.Name, inst.Status, inst.Version)
    }
    
    // 停止插件
    if err := host.StopPlugin("logengine"); err != nil {
        log.Fatal(err)
    }
}
```

---

## 5. 最佳实践

### 5.1 适配器设计原则

✅ **推荐做法**:

1. **单一职责**: 每个适配器只负责一种外部系统的适配
2. **依赖倒置**: 适配器依赖领域层定义的端口（接口）
3. **错误转换**: 将基础设施错误转换为领域错误
4. **数据转换**: 在适配器层完成领域模型与外部模型的转换
5. **可测试性**: 适配器应该易于 Mock 和测试

❌ **避免做法**:

1. **领域逻辑泄露**: 业务逻辑不应该在适配器中
2. **直接依赖基础设施**: 领域层不应该直接依赖适配器
3. **跨适配器调用**: 适配器之间不应该直接调用
4. **忽略错误处理**: 适配器应该妥善处理所有错误

### 5.2 错误处理

```go
// ✅ 好的做法：错误转换
func (a *FileAdapter) Save(rule *Rule) error {
    data, err := json.Marshal(rule)
    if err != nil {
        // 将基础设施错误转换为领域错误
        return domain.ErrSerializationFailed{Cause: err}
    }
    
    if err := os.WriteFile(path, data, 0644); err != nil {
        return domain.ErrPersistenceFailed{Cause: err}
    }
    
    return nil
}

// ❌ 不好的做法：直接返回基础设施错误
func (a *FileAdapter) Save(rule *Rule) error {
    data, err := json.Marshal(rule)
    if err != nil {
        return err // 直接返回，调用方不知道是什么错误
    }
    return os.WriteFile(path, data, 0644)
}
```

### 5.3 数据转换

```go
// ✅ 好的做法：集中转换逻辑
type Converter struct{}

func (c *Converter) ToDomain(entry *BPFEntry) (*Rule, error) {
    return &Rule{
        ID:       entry.Key.ID,
        SourceIP: toIPNet(entry.Value.SourceIP, entry.Value.SourceMask),
        DestIP:   toIPNet(entry.Value.DestIP, entry.Value.DestMask),
        // ...
    }, nil
}

func (c *Converter) ToBPF(rule *Rule) (*BPFEntry, error) {
    return &BPFEntry{
        Key: BPFKey{ID: hash(rule)},
        Value: BPFValue{
            SourceIP:   toUint32(rule.SourceIP),
            DestIP:     toUint32(rule.DestIP),
            // ...
        },
    }, nil
}

// ❌ 不好的做法：转换逻辑分散
// 在每个使用地方都写一遍转换代码
```

### 5.4 测试适配器

```go
// ✅ 好的做法：使用 Mock
func TestRuleService(t *testing.T) {
    // 创建 Mock 仓库
    mockRepo := &MockRuleRepository{}
    
    // 创建服务
    service := services.NewRuleService(mockRepo, validator, publisher)
    
    // 测试
    rule, err := service.CreateRule(cmd)
    if err != nil {
        t.Fatal(err)
    }
    
    // 验证
    if rule.ID != "test" {
        t.Errorf("expected test, got %s", rule.ID)
    }
}

// Mock 实现
type MockRuleRepository struct {
    rules map[string]*Rule
}

func (m *MockRuleRepository) Save(rule *Rule) error {
    m.rules[rule.ID] = rule
    return nil
}
```

### 5.5 性能优化

```go
// ✅ 好的做法：批量操作
func (a *DataPathAdapter) SyncRules(rules []*Rule) error {
    // 批量转换
    entries := make([]*BPFEntry, 0, len(rules))
    for _, rule := range rules {
        entry, err := a.converter.ToBPF(rule)
        if err != nil {
            return err
        }
        entries = append(entries, entry)
    }
    
    // 批量更新（一次系统调用）
    return a.xdpMgr.BatchUpdate(entries)
}

// ❌ 不好的做法：逐个操作
func (a *DataPathAdapter) SyncRules(rules []*Rule) error {
    for _, rule := range rules {
        entry, err := a.converter.ToBPF(rule)
        if err != nil {
            return err
        }
        // 每次都是单独的系统调用
        if err := a.xdpMgr.Update(entry); err != nil {
            return err
        }
    }
    return nil
}
```

---

## 附录

### A. 相关文件

- [`adapters/configfile/`](file:///root/work1/netxfw/netxfw/internal/adapters/configfile/) - 配置文件适配器
- `adapters/datapath/` - 数据平面适配器（规划中）
- [`adapters/plugins/`](file:///root/work1/netxfw/netxfw/internal/adapters/plugins/) - 插件运行时适配器
- [`api/`](file:///root/work1/netxfw/netxfw/internal/api/) - HTTP API 适配器

### B. 参考资源

- 《Clean Architecture》- Robert C. Martin
- 《Implementing Domain-Driven Design》- Vaughn Vernon
- [Hexagonal Architecture](https://alistair.cockburn.us/hexagonal-architecture/)

---

**文档维护**: NetXFW 开发团队  
**最后更新**: 2026-04-19
