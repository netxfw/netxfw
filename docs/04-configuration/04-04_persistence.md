# NetXFW 配置持久化机制

**版本**: v2.0  
**最后更新**: 2026-04-19  
**状态**: 已实施

---

## 📋 目录

1. [概述](#1-概述)
2. [配置存储架构](#2-配置存储架构)
3. [配置文件格式](#3-配置文件格式)
4. [持久化机制](#4-持久化机制)
5. [快照与恢复](#5-快照与恢复)
6. [自动同步](#6-自动同步)
7. [最佳实践](#7-最佳实践)

---

## 1. 概述

### 1.1 配置持久化的重要性

NetXFW 作为一个高性能防火墙，配置持久化机制确保：

- **数据不丢失**: 系统重启后配置自动恢复
- **一致性**: 内存配置与磁盘配置保持一致
- **可恢复**: 支持配置快照和回滚
- **原子性**: 配置更新要么完全成功，要么完全失败
- **高性能**: 最小化对系统性能的影响

### 1.2 配置层次

NetXFW 的配置分为三个层次：

```
┌─────────────────────────────────────────────────────────────┐
│                    NetXFW 配置层次                           │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              运行时配置 (Runtime)                    │   │
│  │  • BPF Map 中的实时规则                             │   │
│  │  • 内存中的配置对象                                 │   │
│  │  • 毫秒级访问速度                                   │   │
│  └─────────────────────────────────────────────────────┘   │
│                          │                                  │
│                          │ 持久化                           │
│                          ▼                                  │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              持久化配置 (Persistent)                 │   │
│  │  • config.toml (主配置文件)                         │   │
│  │  • snapshots/ (配置快照)                            │   │
│  │  • rules/ (规则文件)                                │   │
│  │  • 秒级访问速度                                     │   │
│  └─────────────────────────────────────────────────────┘   │
│                          │                                  │
│                          │ 备份                             │
│                          ▼                                  │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              备份配置 (Backup)                       │   │
│  │  • 远程存储                                         │   │
│  │  • 版本控制                                         │   │
│  │  • 分钟级访问速度                                   │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 2. 配置存储架构

### 2.1 存储位置

```
/etc/netxfw/
├── config.toml                    # 主配置文件
├── config.toml.lock               # 配置文件锁（防止并发写入）
├── snapshots/                     # 配置快照目录
│   ├── config-20260419-120000.toml
│   ├── config-20260419-130000.toml
│   └── config-20260419-140000.toml
├── rules/                         # 规则文件目录
│   ├── blacklist.toml
│   ├── whitelist.toml
│   └── custom_rules.toml
└── backups/                       # 备份目录（可选，远程存储）
    └── ...
```

### 2.2 配置缓存

为了提高性能，NetXFW 使用多级缓存机制：

```go
// internal/domain/config/cache.go

// 配置缓存
type ConfigCache struct {
    // 一级缓存：内存中的配置对象
    config *Config
    
    // 二级缓存：配置的哈希值（用于快速检测变更）
    hash string
    
    // 最后加载时间
    lastLoad time.Time
    
    // 缓存 TTL
    ttl time.Duration
    
    mu sync.RWMutex
}

// 获取配置（带缓存）
func (c *ConfigCache) Get() (*Config, error) {
    c.mu.RLock()
    defer c.mu.RUnlock()
    
    // 检查缓存是否过期
    if c.config != nil && time.Since(c.lastLoad) < c.ttl {
        return c.config, nil
    }
    
    return nil, ErrCacheMiss
}

// 设置配置
func (c *ConfigCache) Set(cfg *Config) {
    c.mu.Lock()
    defer c.mu.Unlock()
    
    c.config = cfg
    c.hash = calculateHash(cfg)
    c.lastLoad = time.Now()
}

// 检查配置是否变更
func (c *ConfigCache) HasChanged(oldHash string) bool {
    c.mu.RLock()
    defer c.mu.RUnlock()
    return c.hash != oldHash
}
```

### 2.3 双检锁模式

```go
// internal/adapters/configfile/cache.go

var (
    configCache *domainconfig.Config
    configMu    sync.RWMutex
    lastLoad    time.Time
    cacheTTL    = 5 * time.Second
)

// getCachedConfig 获取缓存的配置（双检锁模式）
func getCachedConfig() (*domainconfig.Config, error) {
    // 第一次检查（读锁）
    configMu.RLock()
    if configCache != nil && time.Since(lastLoad) < cacheTTL {
        configMu.RUnlock()
        return configCache, nil
    }
    configMu.RUnlock()
    
    // 获取写锁
    configMu.Lock()
    defer configMu.Unlock()
    
    // 第二次检查（写锁）
    if configCache != nil && time.Since(lastLoad) < cacheTTL {
        return configCache, nil
    }
    
    // 重新加载配置
    cfg, err := Load("config.toml")
    if err != nil {
        return nil, err
    }
    
    configCache = cfg
    lastLoad = time.Now()
    return cfg, nil
}
```

---

## 3. 配置文件格式

### 3.1 主配置文件

```toml
# /etc/netxfw/config.toml

# 版本信息
version = "2.0"

# 网络配置
[network]
interfaces = ["eth0", "eth1"]
mode = "inline"  # inline, tap, hybrid

# 安全配置
[security]
token = "your-secret-token-here"
rate_limit = 1000  # 每秒请求数
brute_force_protection = true

# 日志配置
[logging]
level = "info"  # debug, info, warn, error
format = "json"  # json, console
output = "/var/log/netxfw/netxfw.log"

# 数据平面配置
[datapath]
xdp_mode = "native"  # native, skb, generic
map_size = 65536  # BPF Map 大小
plugin_slots = 14  # 插件槽位数量

# 持久化配置
[persistence]
enabled = true
auto_save = true
auto_save_interval = 60  # 秒
snapshot_enabled = true
max_snapshots = 10
```

### 3.2 规则文件

```toml
# /etc/netxfw/rules/blacklist.toml

[[rules]]
id = "block-malicious-ip"
name = "阻止恶意 IP"
enabled = true
priority = 10
action = "deny"

[rules.match]
source_ip = "203.0.113.0/24"
protocol = "any"

[[rules]]
id = "block-ssh-bruteforce"
name = "阻止 SSH 暴力破解"
enabled = true
priority = 20
action = "limit"

[rules.match]
dest_port = 22
protocol = "tcp"

[rules.limit]
rate = 10  # 每秒 10 个连接
burst = 50  # 突发 50 个连接
```

### 3.3 配置哈希计算

```go
// internal/domain/config/hash.go

// 计算配置哈希（用于检测变更）
func calculateHash(cfg *Config) string {
    hasher := sha256.New()
    
    // 序列化配置
    encoder := toml.NewEncoder(hasher)
    encoder.Encode(cfg)
    
    // 返回十六进制哈希
    return hex.EncodeToString(hasher.Sum(nil))
}

// 快速比较配置是否变更
func HasConfigChanged(oldHash, newHash string) bool {
    return oldHash != newHash
}
```

---

## 4. 持久化机制

### 4.1 原子写入

NetXFW 使用原子写入确保配置文件的完整性：

```go
// internal/adapters/configfile/save.go

func Save(cfg *domainconfig.Config, path string) error {
    // 1. 编码配置
    data, err := Encode(cfg)
    if err != nil {
        return fmt.Errorf("encode config failed: %w", err)
    }
    
    // 2. 确保目录存在
    dir := filepath.Dir(path)
    if err := os.MkdirAll(dir, 0755); err != nil {
        return fmt.Errorf("create directory failed: %w", err)
    }
    
    // 3. 写入临时文件（原子操作第一步）
    tmpPath := path + ".tmp." + fmt.Sprintf("%d", time.Now().UnixNano())
    if err := os.WriteFile(tmpPath, data, 0644); err != nil {
        return fmt.Errorf("write temp file failed: %w", err)
    }
    
    // 4. 同步到磁盘（确保数据落盘）
    if err := syncFile(tmpPath); err != nil {
        os.Remove(tmpPath)
        return fmt.Errorf("sync file failed: %w", err)
    }
    
    // 5. 重命名临时文件到目标文件（原子操作第二步）
    if err := os.Rename(tmpPath, path); err != nil {
        os.Remove(tmpPath)
        return fmt.Errorf("rename file failed: %w", err)
    }
    
    // 6. 同步目录（确保目录条目更新）
    if err := syncDirectory(dir); err != nil {
        return fmt.Errorf("sync directory failed: %w", err)
    }
    
    return nil
}

// syncFile 同步文件到磁盘
func syncFile(path string) error {
    f, err := os.Open(path)
    if err != nil {
        return err
    }
    defer f.Close()
    
    return f.Sync()
}

// syncDirectory 同步目录到磁盘
func syncDirectory(dir string) error {
    f, err := os.Open(dir)
    if err != nil {
        return err
    }
    defer f.Close()
    
    return f.Sync()
}
```

### 4.2 文件锁

防止多个进程同时写入配置文件：

```go
// internal/adapters/configfile/lock.go

import "github.com/gofrs/flock"

// FileLock 配置文件锁
type FileLock struct {
    lock *flock.Flock
}

// Acquire 获取锁
func (l *FileLock) Acquire(path string) error {
    l.lock = flock.New(path + ".lock")
    
    // 尝试获取锁（非阻塞）
    acquired, err := l.lock.TryLock()
    if err != nil {
        return err
    }
    
    if !acquired {
        return ErrConfigLocked
    }
    
    return nil
}

// Release 释放锁
func (l *FileLock) Release() error {
    if l.lock != nil {
        return l.lock.Unlock()
    }
    return nil
}

// 使用示例
func SaveWithLock(cfg *Config, path string) error {
    lock := &FileLock{}
    
    // 获取锁
    if err := lock.Acquire(path); err != nil {
        return err
    }
    defer lock.Release()
    
    // 保存配置
    return Save(cfg, path)
}
```

### 4.3 配置同步流程

```
┌─────────────────────────────────────────────────────────────┐
│                  配置同步流程图                              │
└─────────────────────────────────────────────────────────────┘

用户修改配置
     │
     ▼
┌─────────────────┐
│  验证配置合法性  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  获取文件锁     │◀────── 失败 ──────▶ 返回错误
└────────┬────────┘
         │ 成功
         ▼
┌─────────────────┐
│  编码为 TOML    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  写入临时文件   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  同步到磁盘     │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  重命名临时文件 │ (原子操作)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  同步目录       │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  释放文件锁     │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  更新内存缓存   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  发布配置变更事件│
└────────┬────────┘
         │
         ▼
    完成
```

---

## 5. 快照与恢复

### 5.1 创建快照

```go
// internal/adapters/configfile/snapshot.go

// CreateSnapshot 创建配置快照
func CreateSnapshot(cfg *domainconfig.Config) (string, error) {
    // 生成快照 ID（时间戳格式）
    snapshotID := time.Now().Format("20060102-150405")
    
    // 快照文件路径
    snapshotDir := getSnapshotDir()
    snapshotPath := filepath.Join(
        snapshotDir,
        fmt.Sprintf("config-%s.toml", snapshotID),
    )
    
    // 确保快照目录存在
    if err := os.MkdirAll(snapshotDir, 0755); err != nil {
        return "", err
    }
    
    // 保存快照
    if err := Save(cfg, snapshotPath); err != nil {
        return "", err
    }
    
    // 清理旧快照（保留最近的 N 个）
    if err := cleanupOldSnapshots(snapshotDir, 10); err != nil {
        log.Printf("清理旧快照失败：%v", err)
    }
    
    return snapshotID, nil
}

// cleanupOldSnapshots 清理旧快照
func cleanupOldSnapshots(dir string, maxCount int) error {
    // 列出所有快照
    files, err := os.ReadDir(dir)
    if err != nil {
        return err
    }
    
    // 按时间排序
    sort.Slice(files, func(i, j int) bool {
        return files[i].Name() > files[j].Name()
    })
    
    // 删除旧快照
    if len(files) > maxCount {
        for i := maxCount; i < len(files); i++ {
            filePath := filepath.Join(dir, files[i].Name())
            if err := os.Remove(filePath); err != nil {
                log.Printf("删除旧快照失败 %s: %v", filePath, err)
            }
        }
    }
    
    return nil
}
```

### 5.2 恢复快照

```go
// internal/adapters/configfile/restore.go

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
    cfg, err := Load(snapshotPath)
    if err != nil {
        return nil, fmt.Errorf("load snapshot failed: %w", err)
    }
    
    return cfg, nil
}

// ListSnapshots 列出所有快照
func ListSnapshots() ([]SnapshotInfo, error) {
    snapshotDir := getSnapshotDir()
    
    files, err := os.ReadDir(snapshotDir)
    if err != nil {
        return nil, err
    }
    
    snapshots := make([]SnapshotInfo, 0)
    for _, file := range files {
        if strings.HasPrefix(file.Name(), "config-") && strings.HasSuffix(file.Name(), ".toml") {
            // 解析快照 ID
            snapshotID := strings.TrimSuffix(
                strings.TrimPrefix(file.Name(), "config-"),
                ".toml",
            )
            
            // 获取文件信息
            info, err := file.Info()
            if err != nil {
                continue
            }
            
            snapshots = append(snapshots, SnapshotInfo{
                ID:        snapshotID,
                Time:      info.ModTime(),
                Size:      info.Size(),
                Checksum:  calculateFileChecksum(filepath.Join(snapshotDir, file.Name())),
            })
        }
    }
    
    // 按时间倒序排序
    sort.Slice(snapshots, func(i, j int) bool {
        return snapshots[i].Time.After(snapshots[j].Time)
    })
    
    return snapshots, nil
}

type SnapshotInfo struct {
    ID       string
    Time     time.Time
    Size     int64
    Checksum string
}
```

### 5.3 自动快照

```go
// internal/application/services/config_service.go

// ConfigService 配置服务
type ConfigService struct {
    config      *domainconfig.Config
    persister   ConfigPersister
    eventBus    EventBus
    autoSaveCh  chan struct{}
    mu          sync.RWMutex
}

// StartAutoSnapshot 启动自动快照
func (s *ConfigService) StartAutoSnapshot(interval time.Duration) {
    ticker := time.NewTicker(interval)
    
    go func() {
        for range ticker.C {
            // 检查配置是否变更
            if s.hasConfigChanged() {
                // 创建快照
                snapshotID, err := s.persister.CreateSnapshot(s.config)
                if err != nil {
                    log.Printf("自动快照失败：%v", err)
                    continue
                }
                
                log.Printf("自动快照创建成功：%s", snapshotID)
                
                // 发布事件
                s.eventBus.Publish("config.snapshot.created", SnapshotEvent{
                    SnapshotID: snapshotID,
                    Time:       time.Now(),
                })
            }
        }
    }()
}

// hasConfigChanged 检查配置是否变更
func (s *ConfigService) hasConfigChanged() bool {
    s.mu.RLock()
    defer s.mu.RUnlock()
    
    // 加载当前配置
    currentCfg, err := s.persister.Load("config.toml")
    if err != nil {
        return false
    }
    
    // 比较哈希
    return calculateHash(s.config) != calculateHash(currentCfg)
}
```

---

## 6. 自动同步

### 6.1 Map 到文件的同步

```go
// internal/application/services/sync_service.go

// SyncService 同步服务
type SyncService struct {
    xdpMgr      *xdp.Manager
    persister   ConfigPersister
    eventBus    EventBus
    autoSyncCh  chan struct{}
    isDirty     bool
    mu          sync.RWMutex
}

// StartAutoSync 启动自动同步
func (s *SyncService) StartAutoSync(interval time.Duration) {
    ticker := time.NewTicker(interval)
    
    go func() {
        for range ticker.C {
            if s.isDirty {
                if err := s.Map2File(); err != nil {
                    log.Printf("自动同步失败：%v", err)
                    continue
                }
                
                s.isDirty = false
                
                log.Printf("自动同步完成")
            }
        }
    }()
}

// Map2File 将内存中的配置同步到文件
func (s *SyncService) Map2File() error {
    s.mu.Lock()
    defer s.mu.Unlock()
    
    // 从 BPF Map 读取当前规则
    rules, err := s.xdpMgr.GetAllRules()
    if err != nil {
        return err
    }
    
    // 更新配置
    s.config.Rules = rules
    
    // 保存到文件
    return s.persister.Save(s.config, "config.toml")
}

// File2Map 从文件加载配置到内存
func (s *SyncService) File2Map() error {
    s.mu.Lock()
    defer s.mu.Unlock()
    
    // 从文件加载配置
    cfg, err := s.persister.Load("config.toml")
    if err != nil {
        return err
    }
    
    // 更新配置
    s.config = cfg
    
    // 同步到 BPF Map
    return s.xdpMgr.UpdateRules(cfg.Rules)
}

// MarkDirty 标记配置已修改（需要同步）
func (s *SyncService) MarkDirty() {
    s.mu.Lock()
    defer s.mu.Unlock()
    s.isDirty = true
}
```

### 6.2 同步策略

```go
// internal/application/services/sync_policy.go

// SyncPolicy 同步策略
type SyncPolicy int

const (
    // SyncImmediate 立即同步
    SyncImmediate SyncPolicy = iota
    
    // SyncDelayed 延迟同步（批量操作）
    SyncDelayed
    
    // SyncManual 手动同步
    SyncManual
)

// SyncOptions 同步选项
type SyncOptions struct {
    Policy      SyncPolicy
    Timeout     time.Duration
    RetryCount  int
}

// SyncWithPolicy 根据策略同步
func (s *SyncService) SyncWithPolicy(opt SyncOptions) error {
    switch opt.Policy {
    case SyncImmediate:
        // 立即同步
        return s.Map2File()
        
    case SyncDelayed:
        // 延迟同步（等待批量操作完成）
        select {
        case <-time.After(opt.Timeout):
            return s.Map2File()
        case <-s.autoSyncCh:
            // 被其他操作触发
            return s.Map2File()
        }
        
    case SyncManual:
        // 手动同步（由用户触发）
        return nil
    }
    
    return nil
}
```

---

## 7. 最佳实践

### 7.1 配置管理

✅ **推荐做法**:

1. **使用配置文件版本控制**: 记录每次配置变更
2. **定期创建快照**: 在重大变更前创建快照
3. **启用自动同步**: 防止配置丢失
4. **使用原子写入**: 确保配置文件完整性
5. **备份配置**: 定期备份到远程存储

❌ **避免做法**:

1. **直接编辑配置文件**: 使用 CLI 或 API 修改
2. **禁用自动同步**: 除非有特殊需求
3. **忽略文件锁**: 可能导致配置损坏
4. **不清理旧快照**: 占用磁盘空间

### 7.2 性能优化

```go
// ✅ 好的做法：批量同步
func (s *SyncService) BatchUpdate(rules []*Rule) error {
    // 标记为脏数据
    s.MarkDirty()
    
    // 批量更新 BPF Map
    return s.xdpMgr.BatchUpdate(rules)
    
    // 延迟同步（等待批量操作完成）
    // 由自动同步服务处理
}

// ❌ 不好的做法：逐个同步
func (s *SyncService) Update(rule *Rule) error {
    // 更新 BPF Map
    if err := s.xdpMgr.Update(rule); err != nil {
        return err
    }
    
    // 立即同步到文件（性能差）
    return s.Map2File()
}
```

### 7.3 错误处理

```go
// ✅ 好的做法：完善的错误处理
func SaveWithRetry(cfg *Config, path string) error {
    maxRetries := 3
    var lastErr error
    
    for i := 0; i < maxRetries; i++ {
        if err := Save(cfg, path); err == nil {
            return nil
        } else {
            lastErr = err
            log.Printf("保存配置失败 (尝试 %d/%d): %v", i+1, maxRetries, err)
            time.Sleep(100 * time.Millisecond)
        }
    }
    
    return fmt.Errorf("保存配置失败，已重试 %d 次：%w", maxRetries, lastErr)
}

// ❌ 不好的做法：忽略错误
func Save(cfg *Config, path string) {
    Save(cfg, path) // 不检查错误
}
```

### 7.4 监控与告警

```go
// internal/metrics/config_metrics.go

// 配置同步指标
var (
    configSyncDuration = prometheus.NewHistogram(
        prometheus.HistogramOpts{
            Name:    "netxfw_config_sync_duration_seconds",
            Help:    "配置同步耗时",
            Buckets: prometheus.ExponentialBuckets(0.001, 2, 10),
        },
    )
    
    configSyncErrors = prometheus.NewCounter(
        prometheus.CounterOpts{
            Name: "netxfw_config_sync_errors_total",
            Help: "配置同步错误次数",
        },
    )
    
    configSnapshotsTotal = prometheus.NewCounter(
        prometheus.CounterOpts{
            Name: "netxfw_config_snapshots_total",
            Help: "配置快照创建总数",
        },
    )
)

// 记录同步耗时
func (s *SyncService) Map2File() error {
    start := time.Now()
    defer func() {
        configSyncDuration.Observe(time.Since(start).Seconds())
    }()
    
    if err := s.Map2File(); err != nil {
        configSyncErrors.Inc()
        return err
    }
    
    return nil
}
```

---

## 附录

### A. 相关文件

- [`internal/adapters/configfile/`](file:///root/work1/netxfw/netxfw/internal/adapters/configfile/) - 配置文件适配器
- [`internal/domain/config/`](file:///root/work1/netxfw/netxfw/internal/domain/config/) - 配置领域模型
- [`internal/application/services/`](file:///root/work1/netxfw/netxfw/internal/application/services/) - 应用服务

### B. 配置示例

- [`config.toml`](file:///root/work1/netxfw/netxfw/config.toml) - 默认配置文件
- [`docs/04-configuration/04-03_configuration_reference.md`](file:///root/work1/netxfw/netxfw/docs/04-configuration/04-03_configuration_reference.md) - 配置参考文档

### C. 命令参考

```bash
# 查看配置
netxfw config show

# 修改配置
netxfw config set logging.level debug

# 创建快照
netxfw config snapshot create

# 列出快照
netxfw config snapshot list

# 恢复快照
netxfw config snapshot restore <snapshot-id>

# 同步配置
netxfw config sync
```

---

**文档维护**: NetXFW 开发团队  
**最后更新**: 2026-04-19
