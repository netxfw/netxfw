# 配置更新摘要 (Configuration Update Summary)

## 更新日期 / Update Date
2026-03-13

## 更新内容 / Update Content

### 1. 配置文件更新 / Configuration Files Updated

#### `/root/netxfw/config/config-agent.toml`
- ✅ 按照 `config_toml.go` 模板重新排序配置项
- ✅ 添加完整的 IPv4/IPv6 双栈示例
- ✅ 统一 action 定义：`0 = Deny`, `1 = Allow`
- ✅ 添加详细的中英文注释

**主要配置章节：**
1. Core Configuration / 核心配置
2. Security Rules / 安全规则
3. XDP Configuration / XDP 配置
4. Services / 服务
5. Logging / 日志
6. Advanced / 高级配置

### 2. 文档更新 / Documentation Updated

#### `docs/04-configuration/04-03_configuration_reference.md`
- ✅ 更新白名单示例，添加 IPv6 地址
- ✅ 更新 IP-端口规则示例，添加 IPv6 规则
- ✅ 更新速率限制示例，添加 IPv6 速率限制
- ✅ 更新可信负载均衡范围示例，添加 IPv6 范围
- ✅ 详细说明 IPv4/IPv6 掩码配置

#### `docs/05-advanced-features/config_example.toml`
- ✅ 重写为完整的 IPv4/IPv6 双栈配置示例
- ✅ 包含 8 个主要配置部分
- ✅ 每个配置项都有中英文双语注释

---

## IPv6 配置示例 / IPv6 Configuration Examples

### 1. 白名单 (Whitelist)
```toml
whitelist = [
    # IPv6 Addresses
    "::1/128",                # IPv6 loopback
    "fe80::/10",              # Link-local
    "2001:db8::/32",          # Documentation
    "2400:3200::/32",         # Public range
]
```

### 2. IP-端口规则 (IP-Port Rules)
```toml
ip_port_rules = [
    # IPv6 Rules
    { ip = "::/0", port = 22, action = 1 },   # Allow all IPv6 SSH
    { ip = "::/0", port = 80, action = 1 },   # Allow all IPv6 HTTP
    { ip = "::/0", port = 443, action = 1 },  # Allow all IPv6 HTTPS
]
```

### 3. 速率限制 (Rate Limit)
```toml
rules = [
    # IPv6 Rate Limits
    { ip = "2001:db8::/32", rate = 1000, burst = 2000 },
    { ip = "2400:3200::/32", rate = 800, burst = 1600 },
]
```

### 4. 可信负载均衡 (Trusted LB Ranges)
```toml
trusted_lb_ranges = [
    # IPv6 LB Ranges
    "fc00::/7",               # Unique local
    "2001:db8::/32",          # Documentation
]
```

### 5. 锁定列表掩码 (Lock List Masks)
```toml
lock_list_v4_mask = 24       # /24 = 256 IPs
lock_list_v6_mask = 64       # /64 = Standard subnet
```

---

## 关键变更 / Key Changes

| 配置项 | 旧值 | 新值 | 说明 |
|--------|------|------|------|
| `action` | 不一致 | `0=Deny, 1=Allow` | 统一所有配置的 action 定义 |
| `whitelist` | 仅 IPv4 | IPv4 + IPv6 | 支持双栈配置 |
| `ip_port_rules` | 仅 IPv4 | IPv4 + IPv6 | 支持双栈规则 |
| `rate_limit.rules` | 仅 IPv4 | IPv4 + IPv6 | 支持双栈速率限制 |
| `trusted_lb_ranges` | 仅 IPv4 | IPv4 + IPv6 | 支持双栈负载均衡 |

---

## 常用 IPv6 地址参考 / Common IPv6 Addresses Reference

| 地址类型 | 示例 | 用途 |
|---------|------|------|
| Loopback | `::1/128` | 本地回环 |
| Link-local | `fe80::/10` | 链路本地通信 |
| Unique Local | `fc00::/7` | 私有网络 |
| Documentation | `2001:db8::/32` | 文档示例 |
| Any Address | `::/0` | 所有 IPv6 地址 |

---

## 验证配置 / Validate Configuration

```bash
# 验证配置文件语法
netxfw validate /etc/netxfw/config-agent.toml

# 查看当前配置
netxfw config show

# 测试 IPv6 连接
ping6 -c 4 ipv6.google.com
curl -6 https://ipv6.google.com
```

---

## 相关文档 / Related Documents

- [配置参考文档](04-03_configuration_reference.md)
- [配置示例](../05-advanced-features/config_example.toml)
- [配置文件](../../config/config-agent.toml)
- [代码模板](../../internal/plugins/types/config_toml.go)

---

## 注意事项 / Notes

1. **IPv6 掩码建议**: 推荐使用 `/64` 作为标准子网掩码
2. **双栈配置**: 建议同时配置 IPv4 和 IPv6 规则以确保完整覆盖
3. **action 统一**: 所有配置文件中 `action` 值统一定义为 `0=Deny, 1=Allow`
4. **配置顺序**: 配置文件已按照代码模板顺序重新组织

---

## 测试用例 / Test Cases

### 1. 白名单测试
```bash
# IPv6 白名单应该允许访问
ping6 -c 4 <IPv6_whitelist_IP>
```

### 2. IP-端口规则测试
```bash
# 测试 IPv6 HTTP 访问
curl -6 http://[IPv6_address]:80
```

### 3. 速率限制测试
```bash
# 测试 IPv6 速率限制
for i in {1..1000}; do curl -6 http://[IPv6_address]; done
```

### 4. 负载均衡测试
```bash
# 验证 PROXY 协议解析
curl -6 -H "X-Forwarded-For: <IPv6_LB_IP>" http://backend
```
