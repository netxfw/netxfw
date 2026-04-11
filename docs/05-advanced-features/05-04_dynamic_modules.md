# 动态模块顺序

## 概述

NetXFW 支持运行时动态调整 XDP 模块的执行顺序，无需重新编译 BPF 程序。通过配置文件定义模块优先级，系统自动构建执行链，实现灵活的防火墙策略。

## 架构设计

### 核心机制

```
┌─────────────────────────────────────────────────────────────┐
│                    配置文件 (config.toml)                     │
│  modules:                                                    │
│    - name: "sanity"        priority: 0                       │
│    - name: "critical_blacklist" priority: 10                 │
│    - name: "whitelist"     priority: 20                      │
│    ...                                                       │
└──────────────────────────┬──────────────────────────────────┘
                           │ SyncModules()
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                    chain_map (ARRAY)                         │
│  ┌─────────┬───────────────────────────────────────────┐    │
│  │ Key     │ Value (jmp_table index)                   │    │
│  ├─────────┼───────────────────────────────────────────┤    │
│  │ 0 (ENTRY)│ → 20 (sanity's jmp_idx)                  │    │
│  │ 1 (SANITY)│ → 21 (critical's jmp_idx)               │    │
│  │ 2 (CRITICAL)│ → 22 (whitelist's jmp_idx)            │    │
│  │ ...     │                                           │    │
│  └─────────┴───────────────────────────────────────────┘    │
└──────────────────────────┬──────────────────────────────────┘
                           │ bpf_tail_call()
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                    jmp_table (PROG_ARRAY)                    │
│  ┌─────────┬───────────────────────────────────────────┐    │
│  │ Index   │ BPF Program                               │    │
│  ├─────────┼───────────────────────────────────────────┤    │
│  │ 20      │ xdp_sanity                                │    │
│  │ 21      │ xdp_critical                              │    │
│  │ 22      │ xdp_whitelist                             │    │
│  │ ...     │                                           │    │
│  │ 0       │ xdp_ipv4 (protocol handler)               │    │
│  │ 1       │ xdp_ipv6 (protocol handler)               │    │
│  │ 2-15    │ 插件槽位 (预留)                            │    │
│  └─────────┴───────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

### BPF 层实现

每个模块通过 `tail_call_next()` 函数实现链式调用：

```c
// bpf/wrappers.bpf.c
static __always_inline int tail_call_next(struct xdp_md *ctx, __u32 current_mod_id) {
    __u32 key = current_mod_id;
    __u32 *next_prog_idx = bpf_map_lookup_elem(&chain_map, &key);
    if (next_prog_idx) {
        bpf_tail_call(ctx, &jmp_table, *next_prog_idx);
    }
    return XDP_PASS;  // 链结束，放行
}

// 模块示例
SEC("xdp/sanity")
int xdp_sanity(struct xdp_md *ctx) {
    // ... 处理逻辑 ...
    return tail_call_next(ctx, MOD_ID_SANITY);  // 跳转下一个
}
```

### Go 层链构建

```go
// internal/xdp/xdp_modules.go
func (m *Manager) SyncModules(configs []types.ModuleConfig) error {
    // 1. 按优先级排序
    sort.Slice(sorted, func(i, j int) bool {
        return sorted[i].Priority < sorted[j].Priority
    })
    
    // 2. 构建链
    for i, cfg := range sorted {
        progIdx := startIdx + uint32(i)
        
        // 更新 jmp_table
        m.jmpTable.Update(progIdx, def.Program, ebpf.UpdateAny)
        
        // 链接上一个模块到此模块
        m.chainMap.Update(previousModID, progIdx, ebpf.UpdateAny)
        
        previousModID = def.ID
    }
    
    // 3. 终止链
    m.chainMap.Delete(previousModID)
}
```

## 可用模块

| 模块名称 | ID | 功能描述 | 建议优先级 |
|----------|-----|----------|------------|
| `sanity` | 1 | 基础验证：Bogon 过滤、分片检查、TCP 标志验证、Land 攻击检测 | 0 |
| `critical_blacklist` | 2 | 危机黑名单：最高优先级封锁，永不自动淘汰 | 10 |
| `whitelist` | 3 | 白名单：全局允许的 IP/CIDR | 20 |
| `blacklist` | 4 | 静态黑名单：手动/CIDR 封锁，持久化 | 30 |
| `dynamic_blacklist` | 5 | 动态黑名单：自动封锁，支持 TTL 自动过期 | 35 |
| `ratelimit` | 6 | 速率限制：防止 DoS/DDoS 攻击 | 40 |
| `conntrack` | 7 | 连接跟踪：维护连接状态 | 50 |
| `ip_port_rules` | 8 | IP+端口规则：精细化的访问控制 | 60 |
| `icmp` | 9 | ICMP 速率限制 | 70 |
| `return_traffic` | 10 | 回程流量放行：无状态回程检查 | 80 |

## 配置示例

### 默认配置

```yaml
# config.toml
modules:
  - name: "sanity"
    enabled: true
    priority: 0
  - name: "critical_blacklist"
    enabled: true
    priority: 10
  - name: "whitelist"
    enabled: true
    priority: 20
  - name: "blacklist"
    enabled: true
    priority: 30
  - name: "dynamic_blacklist"
    enabled: true
    priority: 35
  - name: "ratelimit"
    enabled: true
    priority: 40
  - name: "conntrack"
    enabled: true
    priority: 50
  - name: "ip_port_rules"
    enabled: true
    priority: 60
  - name: "icmp"
    enabled: true
    priority: 70
  - name: "return_traffic"
    enabled: true
    priority: 80
```

### 高安全模式

优先进行安全检查，延迟放行：

```yaml
modules:
  - name: "sanity"
    enabled: true
    priority: 0
  - name: "critical_blacklist"
    enabled: true
    priority: 10
  - name: "blacklist"
    enabled: true
    priority: 20
  - name: "dynamic_blacklist"
    enabled: true
    priority: 30
  - name: "ratelimit"
    enabled: true
    priority: 40
  - name: "whitelist"
    enabled: true
    priority: 50
  - name: "conntrack"
    enabled: true
    priority: 60
  - name: "ip_port_rules"
    enabled: true
    priority: 70
  - name: "icmp"
    enabled: true
    priority: 80
  - name: "return_traffic"
    enabled: true
    priority: 90
```

### 高性能模式

优先放行已知安全流量：

```yaml
modules:
  - name: "sanity"
    enabled: true
    priority: 0
  - name: "whitelist"
    enabled: true
    priority: 10
  - name: "conntrack"
    enabled: true
    priority: 20
  - name: "return_traffic"
    enabled: true
    priority: 30
  - name: "critical_blacklist"
    enabled: true
    priority: 40
  - name: "blacklist"
    enabled: true
    priority: 50
  - name: "dynamic_blacklist"
    enabled: true
    priority: 60
  - name: "ratelimit"
    enabled: true
    priority: 70
  - name: "ip_port_rules"
    enabled: true
    priority: 80
  - name: "icmp"
    enabled: false
```

## 模块依赖关系

某些模块存在隐式依赖关系，配置时需注意顺序：

```
sanity (必须第一个)
    │
    ▼
critical_blacklist
    │
    ▼
whitelist ←───┐
    │         │
    ▼         │
blacklist     │ conntrack 应在 return_traffic 之前
    │         │
    ▼         │
dynamic_blacklist
    │
    ▼
ratelimit
    │
    ▼
conntrack ─────┘
    │
    ▼
ip_port_rules
    │
    ▼
icmp
    │
    ▼
return_traffic (通常最后)
```

### 依赖规则

| 模块 | 依赖 | 说明 |
|------|------|------|
| `return_traffic` | `conntrack` | 回程流量检查依赖连接状态 |
| `dynamic_blacklist` | `blacklist` | 动态黑名单应在静态之后检查 |
| `whitelist` | - | 应在黑名单之前，确保白名单优先 |

## 热加载

修改模块配置后，发送信号触发热加载：

```bash
# 发送 SIGHUP 信号
sudo kill -HUP $(cat /var/run/netxfw.pid)

# 或使用 CLI
sudo netxfw system reload
```

## 性能考虑

### 尾调用开销

BPF `tail_call` 是零开销跳转：
- 不涉及用户态/内核态切换
- 不保存/恢复寄存器
- 直接跳转到下一个 BPF 程序

### 索引分配

```
┌─────────────────────────────────────────┐
│            jmp_table 索引分配            │
├─────────────────────────────────────────┤
│ 0-1    │ 协议处理器 (ipv4/ipv6)          │
│ 2-15   │ 插件槽位 (用户自定义)           │
│ 16-19  │ 保留                            │
│ 20+    │ 内置模块                        │
└─────────────────────────────────────────┘
```

## API 接口

### 获取当前模块顺序

```bash
GET /api/modules
```

响应示例：

```json
{
  "modules": [
    {"name": "sanity", "enabled": true, "priority": 0},
    {"name": "critical_blacklist", "enabled": true, "priority": 10},
    {"name": "whitelist", "enabled": true, "priority": 20}
  ]
}
```

### 更新模块顺序

```bash
POST /api/modules
Content-Type: application/json

{
  "modules": [
    {"name": "sanity", "enabled": true, "priority": 0},
    {"name": "whitelist", "enabled": true, "priority": 10}
  ]
}
```

## 故障排查

### 模块未生效

1. 检查模块是否启用：
   ```bash
   sudo netxfw system status | grep modules
   ```

2. 检查 chain_map 内容：
   ```bash
   sudo bpftool map dump name chain_map
   ```

3. 检查 jmp_table 内容：
   ```bash
   sudo bpftool map dump name jmp_table
   ```

### 模块顺序错误

查看日志确认链构建过程：

```bash
sudo journalctl -u netxfw -f | grep "Module Linked"
```

预期输出：

```
Module Linked: sanity (ID: 1) -> JmpIdx: 20
Module Linked: critical_blacklist (ID: 2) -> JmpIdx: 21
Module Linked: whitelist (ID: 3) -> JmpIdx: 22
...
```

## 最佳实践

1. **保持 sanity 模块优先级最低**：基础验证应在所有其他模块之前执行
2. **白名单优先于黑名单**：确保可信流量不被误封
3. **conntrack 在 return_traffic 之前**：保证连接状态已建立
4. **禁用不需要的模块**：减少处理开销
5. **测试配置变更**：在生产环境应用前先在测试环境验证
