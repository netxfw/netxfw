# NetXFW 领域驱动设计（DDD）

**版本**: v2.0  
**最后更新**: 2026-04-19  
**状态**: 部分实施（领域模型已建立，部分仓储/加载器接口尚未实现）

---

## 📋 目录

1. [概述](#1-概述)
2. [战略设计](#2-战略设计)
3. [战术设计](#3-战术设计)
4. [领域模型详解](#4-领域模型详解)
5. [架构分层](#5-架构分层)
6. [实践指南](#6-实践指南)

---

## 1. 概述

### 1.1 为什么使用 DDD？

NetXFW 作为一个复杂的可编程防火墙系统，面临以下挑战：

- **业务复杂性**: 规则管理、配置管理、插件系统、数据平面等多个业务领域
- **技术复杂性**: eBPF/XDP 内核态编程、Go 用户态控制、HTTP API、CLI 等多种技术栈
- **扩展性需求**: 需要支持插件扩展、多模式部署（单机/集群/云原生）
- **维护性需求**: 代码需要易于理解、测试和演进

领域驱动设计（DDD）帮助我们：

1. **统一语言**: 建立开发、运维、用户之间的通用语言
2. **边界清晰**: 通过限界上下文明确各模块职责
3. **高内聚低耦合**: 领域内高内聚，领域间低耦合
4. **易于演进**: 领域模型稳定，技术实现可变

### 1.2 核心领域

NetXFW 识别出以下核心领域：

```
┌─────────────────────────────────────────────────────────────┐
│                    NetXFW 核心领域                           │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │   规则领域   │  │   配置领域   │  │   插件领域   │     │
│  │   (Rule)     │  │  (Config)    │  │  (Plugin)    │     │
│  │              │  │              │  │              │     │
│  │ • 防火墙规则 │  │ • 系统配置   │  │ • 插件管理   │     │
│  │ • 黑白名单   │  │ • 运行时配置 │  │ • 扩展点     │     │
│  │ • 限速策略   │  │ • 持久化     │  │ • 生命周期   │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │  运行时领域  │  │   系统领域   │  │  数据平面领域 │     │
│  │  (Runtime)   │  │  (System)    │  │ (DataPath)   │     │
│  │              │  │              │  │              │     │
│  │ • 程序状态   │  │ • 健康检查   │  │ • XDP 程序   │     │
│  │ • 统计信息   │  │ • 性能指标   │  │ • BPF Map    │     │
│  │ • 连接跟踪   │  │ • 错误处理   │  │ • 包处理     │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 2. 战略设计

### 2.1 限界上下文（Bounded Context）

NetXFW 定义了以下限界上下文：

#### 规则上下文（Rule Context）

**职责**: 防火墙规则的定义、验证、存储和执行

**核心概念**:
- `Rule`: 防火墙规则（源/目标 IP、端口、协议、动作）
- `RuleSet`: 规则集合
- `Validator`: 规则验证器
- `Repository`: 规则仓库

**边界**:
- **上游**: 接收来自应用层的规则配置
- **下游**: 将规则转换为数据平面可执行的格式

**示例**:
```go
// domain/rule/rule.go
type Rule struct {
    ID          string
    Name        string
    Description string
    Enabled     bool
    Priority    int
    SourceIP    *net.IPNet
    DestIP      *net.IPNet
    SourcePort  PortRange
    DestPort    PortRange
    Protocol    Protocol
    Action      RuleAction
}

// domain/rule/validator.go
type Validator interface {
    Validate(rule *Rule) error
    ValidateIP(ip net.IP) error
    ValidatePort(port int) error
}
```

#### 配置上下文（Config Context）

**职责**: 系统配置的管理、持久化和热重载

**核心概念**:
- `Config`: 配置模型
- `Loader`: 配置加载器
- `Saver`: 配置保存器
- `Manager`: 配置管理器

**边界**:
- **输入**: 配置文件（TOML/YAML）、环境变量、CLI 参数
- **输出**: 运行时配置对象

**示例**:
```go
// domain/config/config.go
type Config struct {
    Version   string
    Network   NetworkConfig
    Security  SecurityConfig
    Logging   LoggingConfig
    Plugins   PluginConfig
}

// domain/config/loader.go (设计参考，尚未实现)
type Loader interface {
    Load(path string) (*Config, error)
    Validate(cfg *Config) error
}
```

#### 插件上下文（Plugin Context）

**职责**: 插件的生命周期管理、注册和调用

**核心概念**:
- `Plugin`: 插件接口
- `Registry`: 插件注册表
- `Runtime`: 插件运行时
- `Lifecycle`: 生命周期管理

**示例**:
```go
// domain/plugin/plugin.go
type Plugin interface {
    Name() string
    Version() string
    Init(ctx Context) error
    Start() error
    Stop() error
}

// domain/plugin/registry.go (设计参考，尚未实现)
type Registry struct {
    plugins map[string]Plugin
    mu      sync.RWMutex
}
```

#### 运行时上下文（Runtime Context）

**职责**: 运行时状态管理、统计信息收集

**核心概念**:
- `RuntimeState`: 运行时状态
- `Stats`: 统计信息
- `Health`: 健康状态

**示例**:
```go
// domain/runtime/runtime.go (设计参考，实际实现在 actual_state.go)
type RuntimeState struct {
    Status      Status
    Uptime      time.Duration
    StartTime   time.Time
    ConfigHash  string
}

// domain/runtime/stats.go
type Stats struct {
    TotalPackets    uint64
    TotalBytes      uint64
    DroppedPackets  uint64
    PassedPackets   uint64
}
```

#### 系统上下文（System Context）

**职责**: 系统级操作、健康检查、错误处理

**核心概念**:
- `SystemInfo`: 系统信息
- `HealthCheck`: 健康检查
- `Error`: 系统错误

**示例**:
```go
// domain/system/health.go (设计参考，实际实现在 desired_state.go)
type HealthStatus struct {
    Status      string
    Components  []ComponentHealth
    Timestamp   time.Time
}

type ComponentHealth struct {
    Name    string
    Status  string
    Message string
}
```

#### 数据平面上下文（DataPath Context）

**职责**: eBPF/XDP 程序管理、BPF Map 操作

**核心概念**:
- `Program`: eBPF 程序
- `Map`: BPF Map
- `Manager`: 数据平面管理器

**示例**:
```go
// datapath/xdp/programs/program.go
type Program struct {
    Name    string
    Handle  *ebpf.Program
    PinPath string
}

// datapath/xdp/maps/map.go
type Map struct {
    Name    string
    Handle  *ebpf.Map
    PinPath string
}
```

### 2.2 上下文映射（Context Mapping）

```
┌─────────────────────────────────────────────────────────────┐
│                  上下文映射关系                               │
└─────────────────────────────────────────────────────────────┘

     ┌──────────────┐         ┌──────────────┐
     │   CLI/API    │         │  配置文件    │
     │  (用户接口)  │         │  (外部系统)  │
     └───────┬──────┘         └───────┬──────┘
             │                        │
             │ 命令/请求              │ 配置数据
             │                        │
             ▼                        ▼
     ┌──────────────────────────────────────────┐
     │          应用服务层 (Application)         │
     │  ┌────────────────────────────────────┐  │
     │  │  RuleService | ConfigService       │  │
     │  │  PluginService | SystemService     │  │
     │  └────────────────────────────────────┘  │
     └─────────────────┬────────────────────────┘
                       │
                       │ 领域命令/查询
                       │
         ┌─────────────┼─────────────┐
         │             │             │
         ▼             ▼             ▼
┌─────────────┐ ┌─────────────┐ ┌─────────────┐
│  规则领域   │ │  配置领域   │ │  插件领域   │
│  (Rule)     │ │  (Config)   │ │  (Plugin)   │
└──────┬──────┘ └──────┬──────┘ └──────┬──────┘
       │               │               │
       │ 领域事件      │ 领域事件      │ 领域事件
       │               │               │
       ▼               ▼               ▼
┌─────────────────────────────────────────────────┐
│           基础设施层 (Infrastructure)            │
│  ┌──────────────────────────────────────────┐  │
│  │  XDP Manager | Config File | HTTP Server │  │
│  └──────────────────────────────────────────┘  │
└─────────────────────────────────────────────────┘
```

#### 上下文关系说明

1. **应用服务 → 领域**: 依赖关系（应用服务调用领域模型）
2. **领域 → 基础设施**: 依赖倒置（领域定义接口，基础设施实现）
3. **领域 ←→ 领域**: 通过领域事件解耦

---

## 3. 战术设计

### 3.1 实体（Entity）

实体是具有唯一标识和生命周期的领域对象。

#### Rule 实体

```go
// domain/rule/rule.go

// Rule 防火墙规则实体
type Rule struct {
    // 唯一标识
    ID string
    
    // 基本信息
    Name        string
    Description string
    
    // 状态
    Enabled     bool
    Priority    int
    
    // 匹配条件
    SourceIP    *net.IPNet      // 源 IP 段
    DestIP      *net.IPNet      // 目标 IP 段
    SourcePort  PortRange       // 源端口范围
    DestPort    PortRange       // 目标端口范围
    Protocol    Protocol        // 协议类型
    
    // 动作
    Action      RuleAction      // allow/deny/limit/log
    Limit       *LimitConfig    // 限速配置（可选）
    
    // 审计信息
    CreatedAt   time.Time
    UpdatedAt   time.Time
}

// 实体的业务方法
func (r *Rule) Matches(packet *Packet) bool {
    // 检查协议
    if r.Protocol != ProtocolAny && r.Protocol != packet.Protocol {
        return false
    }
    
    // 检查源 IP
    if r.SourceIP != nil && !r.SourceIP.Contains(packet.SrcIP) {
        return false
    }
    
    // 检查目标 IP
    if r.DestIP != nil && !r.DestIP.Contains(packet.DstIP) {
        return false
    }
    
    // 检查端口
    if !r.SourcePort.Contains(packet.SrcPort) {
        return false
    }
    if !r.DestPort.Contains(packet.DstPort) {
        return false
    }
    
    return true
}

func (r *Rule) Validate() error {
    // 验证规则合法性
    if r.Priority < 0 || r.Priority > 1000 {
        return ErrInvalidPriority
    }
    
    if r.Action == ActionLimit && r.Limit == nil {
        return ErrLimitConfigRequired
    }
    
    return nil
}
```

#### Config 实体

```go
// domain/config/config.go

// Config 配置实体
type Config struct {
    // 版本信息
    Version   string
    
    // 网络配置
    Network   NetworkConfig
    
    // 安全配置
    Security  SecurityConfig
    
    // 日志配置
    Logging   LoggingConfig
    
    // 插件配置
    Plugins   PluginConfig
    
    // 配置哈希（用于检测变更）
    hash      string
}

// 实体的业务方法
func (c *Config) Hash() string {
    if c.hash == "" {
        // 计算配置哈希
        c.hash = calculateHash(c)
    }
    return c.hash
}

func (c *Config) HasChanged(old *Config) bool {
    return c.Hash() != old.Hash()
}
```

### 3.2 值对象（Value Object）

值对象是没有唯一标识，通过属性值定义的对象。

#### PortRange 值对象

```go
// domain/rule/port_range.go

// PortRange 端口范围值对象
type PortRange struct {
    Start int
    End   int
}

// 值对象的业务方法
func (p PortRange) Contains(port int) bool {
    return port >= p.Start && port <= p.End
}

func (p PortRange) IsSingle() bool {
    return p.Start == p.End
}

func (p PortRange) String() string {
    if p.IsSingle() {
        return fmt.Sprintf("%d", p.Start)
    }
    return fmt.Sprintf("%d-%d", p.Start, p.End)
}

// 值对象的创建工厂
func NewPortRange(s, e int) (PortRange, error) {
    if s < 0 || e > 65535 || s > e {
        return PortRange{}, ErrInvalidPortRange
    }
    return PortRange{Start: s, End: e}, nil
}
```

#### Protocol 值对象

```go
// domain/rule/protocol.go

// Protocol 协议类型
type Protocol uint8

const (
    ProtocolAny   Protocol = 0
    ProtocolICMP  Protocol = 1
    ProtocolTCP   Protocol = 6
    ProtocolUDP   Protocol = 17
)

func (p Protocol) String() string {
    switch p {
    case ProtocolTCP:
        return "tcp"
    case ProtocolUDP:
        return "udp"
    case ProtocolICMP:
        return "icmp"
    default:
        return "any"
    }
}
```

### 3.3 聚合（Aggregate）

聚合是一组相关对象的集合，作为一个整体进行数据修改。

#### RuleSet 聚合

```go
// domain/rule/ruleset.go

// RuleSet 规则聚合根
type RuleSet struct {
    ID        string
    Name      string
    Rules     []*Rule
    Version   int64
}

// 聚合根的业务方法
func (rs *RuleSet) AddRule(rule *Rule) error {
    // 验证规则
    if err := rule.Validate(); err != nil {
        return err
    }
    
    // 检查 ID 冲突
    for _, r := range rs.Rules {
        if r.ID == rule.ID {
            return ErrRuleExists
        }
    }
    
    // 添加规则
    rs.Rules = append(rs.Rules, rule)
    rs.Version++
    
    return nil
}

func (rs *RuleSet) RemoveRule(id string) error {
    for i, r := range rs.Rules {
        if r.ID == id {
            rs.Rules = append(rs.Rules[:i], rs.Rules[i+1:]...)
            rs.Version++
            return nil
        }
    }
    return ErrRuleNotFound
}

func (rs *RuleSet) UpdateRule(id string, newRule *Rule) error {
    for i, r := range rs.Rules {
        if r.ID == id {
            if err := newRule.Validate(); err != nil {
                return err
            }
            rs.Rules[i] = newRule
            rs.Version++
            return nil
        }
    }
    return ErrRuleNotFound
}

// 按优先级排序
func (rs *RuleSet) SortByPriority() {
    sort.Slice(rs.Rules, func(i, j int) bool {
        return rs.Rules[i].Priority < rs.Rules[j].Priority
    })
}
```

### 3.4 领域服务（Domain Service）

领域服务用于协调多个领域对象完成业务逻辑。

#### RuleService 领域服务

```go
// application/services/rule_service.go

// RuleService 规则领域服务
type RuleService struct {
    ruleRepo    RuleRepository
    validator   Validator
    publisher   EventPublisher
}

func NewRuleService(repo RuleRepository, v Validator, pub EventPublisher) *RuleService {
    return &RuleService{
        ruleRepo:  repo,
        validator: v,
        publisher: pub,
    }
}

// 创建规则
func (s *RuleService) CreateRule(cmd CreateRuleCommand) (*Rule, error) {
    // 创建规则对象
    rule := &Rule{
        ID:          cmd.ID,
        Name:        cmd.Name,
        Description: cmd.Description,
        Enabled:     true,
        Priority:    cmd.Priority,
        SourceIP:    cmd.SourceIP,
        DestIP:      cmd.DestIP,
        SourcePort:  cmd.SourcePort,
        DestPort:    cmd.DestPort,
        Protocol:    cmd.Protocol,
        Action:      cmd.Action,
        Limit:       cmd.Limit,
        CreatedAt:   time.Now(),
        UpdatedAt:   time.Now(),
    }
    
    // 验证规则
    if err := s.validator.Validate(rule); err != nil {
        return nil, err
    }
    
    // 保存规则
    if err := s.ruleRepo.Save(rule); err != nil {
        return nil, err
    }
    
    // 发布领域事件
    s.publisher.Publish(RuleCreatedEvent{
        Rule:    rule,
        Time:    time.Now(),
    })
    
    return rule, nil
}

// 删除规则
func (s *RuleService) DeleteRule(id string) error {
    rule, err := s.ruleRepo.FindByID(id)
    if err != nil {
        return err
    }
    
    if err := s.ruleRepo.Delete(id); err != nil {
        return err
    }
    
    s.publisher.Publish(RuleDeletedEvent{
        RuleID:  id,
        Time:    time.Now(),
    })
    
    return nil
}
```

### 3.5 领域事件（Domain Event）

领域事件用于解耦领域对象之间的依赖。

#### 事件定义

```go
// domain/rule/events.go

// RuleCreatedEvent 规则创建事件
type RuleCreatedEvent struct {
    Rule *Rule
    Time time.Time
}

// RuleUpdatedEvent 规则更新事件
type RuleUpdatedEvent struct {
    Rule    *Rule
    Changes []string
    Time    time.Time
}

// RuleDeletedEvent 规则删除事件
type RuleDeletedEvent struct {
    RuleID string
    Time   time.Time
}

// RuleSyncedEvent 规则同步到数据平面事件
type RuleSyncedEvent struct {
    RuleSet *RuleSet
    Success bool
    Error   error
    Time    time.Time
}
```

#### 事件处理

```go
// internal/api/handlers_rules.go

// 订阅领域事件
func SetupEventHandlers(eventBus EventBus, xdpMgr *xdp.Manager) {
    // 规则变更时同步到数据平面
    eventBus.Subscribe("rule.*", func(event Event) {
        switch e := event.Data.(type) {
        case *RuleCreatedEvent:
            log.Printf("规则已创建：%s", e.Rule.Name)
            // 触发数据平面同步
            
        case *RuleUpdatedEvent:
            log.Printf("规则已更新：%s, 变更：%v", e.Rule.Name, e.Changes)
            // 触发数据平面同步
            
        case *RuleDeletedEvent:
            log.Printf("规则已删除：%s", e.RuleID)
            // 触发数据平面同步
        }
    })
}
```

### 3.6 仓库（Repository）

仓库用于封装领域对象的持久化逻辑。

#### RuleRepository

```go
// domain/rule/repository.go (设计参考，尚未实现)
type RuleRepository interface {
    // 保存规则
    Save(rule *Rule) error
    
    // 查找规则
    FindByID(id string) (*Rule, error)
    FindAll() ([]*Rule, error)
    FindByPriority(min, max int) ([]*Rule, error)
    
    // 删除规则
    Delete(id string) error
    
    // 批量操作
    SaveBatch(rules []*Rule) error
    DeleteBatch(ids []string) error
}

// 内存实现（用于测试）
type InMemoryRuleRepository struct {
    rules map[string]*Rule
    mu    sync.RWMutex
}

func (r *InMemoryRuleRepository) Save(rule *Rule) error {
    r.mu.Lock()
    defer r.mu.Unlock()
    r.rules[rule.ID] = rule
    return nil
}

func (r *InMemoryRuleRepository) FindByID(id string) (*Rule, error) {
    r.mu.RLock()
    defer r.mu.RUnlock()
    rule, ok := r.rules[id]
    if !ok {
        return nil, ErrRuleNotFound
    }
    return rule, nil
}

// 文件实现（用于生产）
type FileRuleRepository struct {
    filePath string
}

func (r *FileRuleRepository) Save(rule *Rule) error {
    // 从文件加载所有规则
    rules, err := r.loadFromFile()
    if err != nil {
        return err
    }
    
    // 更新规则
    rules[rule.ID] = rule
    
    // 保存到文件
    return r.saveToFile(rules)
}
```

---

## 4. 领域模型详解

### 4.1 规则领域模型

```
┌─────────────────────────────────────────────────────────────┐
│                    规则领域模型                               │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────┐      ┌──────────────┐                    │
│  │    Rule      │─────▶│  PortRange   │                    │
│  │  (聚合根)    │      │ (值对象)     │                    │
│  └──────┬───────┘      └──────────────┘                    │
│         │                                                   │
│         │ 包含                                              │
│         ▼                                                   │
│  ┌──────────────┐      ┌──────────────┐                    │
│  │   RuleSet    │      │   Protocol   │                    │
│  │  (聚合根)    │      │ (值对象)     │                    │
│  └──────┬───────┘      └──────────────┘                    │
│         │                                                   │
│         │ 使用                                              │
│         ▼                                                   │
│  ┌──────────────┐      ┌──────────────┐                    │
│  │  Validator   │      │ RuleAction   │                    │
│  │ (领域服务)   │      │ (值对象)     │                    │
│  └──────────────┘      └──────────────┘                    │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 4.2 配置领域模型

```
┌─────────────────────────────────────────────────────────────┐
│                    配置领域模型                               │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────┐                                           │
│  │    Config    │ (聚合根)                                  │
│  └──────┬───────┘                                           │
│         │                                                   │
│    ┌────┴────┬────────────┬────────────┐                   │
│    │         │            │            │                   │
│    ▼         ▼            ▼            ▼                   │
│ ┌──────┐ ┌──────┐    ┌──────────┐ ┌──────────┐            │
│ │Network│ │Security│  │ Logging  │ │ Plugins  │            │
│ │Config │ │Config │   │ Config   │ │ Config   │            │
│ └──────┘ └──────┘    └──────────┘ └──────────┘            │
│                                                             │
│  ┌──────────────┐      ┌──────────────┐                    │
│  │    Loader    │      │    Saver     │                    │
│  │ (领域服务)   │      │ (领域服务)   │                    │
│  └──────────────┘      └──────────────┘                    │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 4.3 插件领域模型

```
┌─────────────────────────────────────────────────────────────┐
│                    插件领域模型                               │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────┐                                           │
│  │   Plugin     │ (接口)                                    │
│  │  +Name()     │                                           │
│  │  +Version()  │                                           │
│  │  +Init()     │                                           │
│  │  +Start()    │                                           │
│  │  +Stop()     │                                           │
│  └──────┬───────┘                                           │
│         │                                                   │
│    实现 │                                                   │
│    ┌───┴───┬───────────┬──────────┐                        │
│    │       │           │          │                        │
│    ▼       ▼           ▼          ▼                        │
│ ┌─────┐ ┌─────┐    ┌───────┐ ┌─────────┐                  │
│ │ Log │ │Metrics│  │  Web  │ │ Custom  │                  │
│ │Engine│ │Plugin │  │Plugin │ │ Plugin  │                  │
│ └─────┘ └─────┘    └───────┘ └─────────┘                  │
│                                                             │
│  ┌──────────────┐      ┌──────────────┐                    │
│  │   Registry   │      │   Runtime    │                    │
│  │ (聚合根)     │      │ (领域服务)   │                    │
│  └──────────────┘      └──────────────┘                    │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 5. 架构分层

### 5.1 四层架构

NetXFW 采用四层架构：

```
┌─────────────────────────────────────────────────────────────┐
│                   用户接口层 (Interfaces)                    │
│  • CLI (cmd/)                                               │
│  • REST API (internal/api/)                                 │
│  • Web UI (plugins/web/)                                    │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                  应用服务层 (Application)                    │
│  • 应用服务 (application/services/)                         │
│  • 端口管理 (application/ports/)                            │
│  • DTO (Data Transfer Objects)                              │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                    领域层 (Domain)                           │
│  • 领域模型 (domain/*/)                                     │
│  • 领域服务                                                 │
│  • 领域事件                                                 │
│  • 仓库接口                                                 │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                基础设施层 (Infrastructure)                   │
│  • 数据平面 (datapath/xdp/)                                 │
│  • 配置持久化 (adapters/configfile/)                        │
│  • HTTP 服务器 (internal/api/)                              │
│  • 日志系统 (internal/utils/logger/)                        │
│  • 仓库实现                                                 │
└─────────────────────────────────────────────────────────────┘
```

### 5.2 依赖规则

**依赖倒置原则**:

```go
// 领域层定义接口 (设计参考)
// domain/rule/repository.go
type RuleRepository interface {
    Save(rule *Rule) error
    FindByID(id string) (*Rule, error)
}

// 基础设施层实现接口 (设计参考)
// internal/adapters/rule_repository.go
type FileRuleRepository struct {
    filePath string
}

func (r *FileRuleRepository) Save(rule *Rule) error {
    // 文件操作实现
}

// 应用层依赖抽象
// application/services/rule_service.go
type RuleService struct {
    ruleRepo RuleRepository  // 依赖接口，而非具体实现
}
```

---

## 6. 实践指南

### 6.1 如何创建新的领域模型

**步骤 1**: 定义实体

```go
// domain/mymodule/entity.go
type MyEntity struct {
    ID        string
    Name      string
    CreatedAt time.Time
}

func (e *MyEntity) Validate() error {
    // 业务验证逻辑
}
```

**步骤 2**: 定义值对象

```go
// domain/mymodule/value_object.go
type MyValueObject struct {
    Field1 string
    Field2 int
}

func (v MyValueObject) IsValid() bool {
    // 验证逻辑
}
```

**步骤 3**: 定义仓库接口

```go
// domain/mymodule/repository.go
type MyRepository interface {
    Save(entity *MyEntity) error
    FindByID(id string) (*MyEntity, error)
}
```

**步骤 4**: 定义领域服务

```go
// application/services/my_service.go
type MyService struct {
    repo MyRepository
}

func NewMyService(repo MyRepository) *MyService {
    return &MyService{repo: repo}
}

func (s *MyService) DoSomething(cmd Command) error {
    // 业务逻辑
}
```

### 6.2 如何处理领域事件

**步骤 1**: 定义事件

```go
// domain/mymodule/events.go
type MyEvent struct {
    EntityID string
    Time     time.Time
}
```

**步骤 2**: 发布事件

```go
// domain/mymodule/entity.go
func (e *MyEntity) DoSomething() {
    // 业务逻辑
    
    // 发布事件
    eventBus.Publish(MyEvent{
        EntityID: e.ID,
        Time:     time.Now(),
    })
}
```

**步骤 3**: 订阅事件

```go
// internal/api/handlers.go
eventBus.Subscribe("my.*", func(event Event) {
    // 处理事件
})
```

### 6.3 如何实现仓库

**内存实现（用于测试）**:

```go
// domain/mymodule/in_memory_repository.go
type InMemoryRepository struct {
    data map[string]*MyEntity
    mu   sync.RWMutex
}

func (r *InMemoryRepository) Save(entity *MyEntity) error {
    r.mu.Lock()
    defer r.mu.Unlock()
    r.data[entity.ID] = entity
    return nil
}
```

**文件实现（用于生产）**:

```go
// internal/adapters/my_repository.go
type FileRepository struct {
    filePath string
}

func (r *FileRepository) Save(entity *MyEntity) error {
    // 加载所有数据
    entities, err := r.load()
    if err != nil {
        return err
    }
    
    // 更新
    entities[entity.ID] = entity
    
    // 保存
    return r.save(entities)
}
```

### 6.4 最佳实践

✅ **推荐做法**:

1. **领域模型纯净**: 领域模型不依赖基础设施（如数据库、HTTP）
2. **业务逻辑内聚**: 业务逻辑放在领域模型中，而非服务层
3. **使用值对象**: 不可变对象，线程安全
4. **领域事件解耦**: 使用事件解耦领域对象
5. **仓库抽象**: 领域层定义接口，基础设施层实现

❌ **避免做法**:

1. **贫血模型**: 只有 getter/setter，没有业务逻辑
2. **依赖基础设施**: 领域模型直接访问数据库或 HTTP
3. **跨领域调用**: 领域间直接调用，而非通过事件
4. **泄露实现细节**: 领域模型暴露基础设施细节

---

## 附录

### A. 相关文件

- [`domain/rule/`](file:///root/work1/netxfw/netxfw/internal/domain/rule/) - 规则领域模型
- [`domain/config/`](file:///root/work1/netxfw/netxfw/internal/domain/config/) - 配置领域模型
- [`domain/plugin/`](file:///root/work1/netxfw/netxfw/internal/domain/plugin/) - 插件领域模型
- [`application/services/`](file:///root/work1/netxfw/netxfw/internal/application/services/) - 应用服务
- [`adapters/`](file:///root/work1/netxfw/netxfw/internal/adapters/) - 适配器层

### B. 参考资源

- 《领域驱动设计》- Eric Evans
- 《实现领域驱动设计》- Vaughn Vernon
- 《Clean Architecture》- Robert C. Martin

---

**文档维护**: NetXFW 开发团队  
**最后更新**: 2026-04-19
