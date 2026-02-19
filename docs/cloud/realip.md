# 云环境真实 IP 获取

## 概述

在云服务商负载均衡器 (LB) 环境下，NetXFW 接收到的连接源 IP 是 LB 的 IP，而非真实客户端 IP。为了解决这个问题，NetXFW 提供了 **Proxy Protocol 解析** 功能，能够从云 LB 转发的流量中提取真实客户端 IP。

## 架构

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                         云环境真实 IP 获取架构                                │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────┐     ┌─────────────┐     ┌─────────────────────────────┐    │
│  │   客户端    │     │   云 LB     │     │         NetXFW              │    │
│  │  真实 IP    │────▶│  Proxy Proto│────▶│  ┌─────────────────────┐   │    │
│  │             │     │  添加头信息  │     │  │  Proxy Protocol     │   │    │
│  └─────────────┘     └─────────────┘     │  │  解析器             │   │    │
│                                          │  └──────────┬──────────┘   │    │
│                                          │             │              │    │
│                                          │             ▼              │    │
│                                          │  ┌─────────────────────┐   │    │
│                                          │  │  真实 IP 管理       │   │    │
│                                          │  │  - 黑名单检查       │   │    │
│                                          │  │  - 自动封禁         │   │    │
│                                          │  └─────────────────────┘   │    │
│                                          └─────────────────────────────┘    │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

## 支持的云服务商

| 云服务商 | 标识符 | Proxy Protocol 支持 |
|----------|--------|---------------------|
| 阿里云 | `alibaba` | ✅ 支持 |
| 腾讯云 | `tencent` | ✅ 支持 |
| AWS | `aws` | ✅ 支持 |
| Azure | `azure` | ✅ 支持 |
| GCP | `gcp` | ✅ 支持 |
| 其他 | `other` | ✅ 支持 (需自定义 IP 范围) |

## 配置

### 配置文件

在 `/etc/netxfw/config.yaml` 中添加云环境配置：

```yaml
# ═══════════════════════════════════════════════════════════════
# Cloud Environment Configuration / 云环境配置
# ═══════════════════════════════════════════════════════════════
cloud:
  # Enable cloud environment support / 启用云环境支持
  enabled: true
  
  # Cloud provider: alibaba, tencent, aws, azure, gcp, other
  # 云服务商: alibaba, tencent, aws, azure, gcp, other
  provider: "alibaba"
  
  # Proxy Protocol configuration / Proxy Protocol 配置
  proxy_protocol:
    # Enable Proxy Protocol parsing / 启用 Proxy Protocol 解析
    enabled: true
    
    # Trusted LB IP ranges (connections from these IPs will be parsed for Proxy Protocol)
    # 可信 LB IP 范围（来自这些 IP 的连接将解析 Proxy Protocol）
    # Predefined ranges will be added based on provider
    # 预定义范围将根据服务商自动添加
    trusted_lb_ranges:
      - "10.0.0.0/8"       # 阿里云/腾讯云内网
      - "100.64.0.0/10"    # 运营商级 NAT
      - "192.168.0.0/16"   # 自定义 VPC
    
    # Cache TTL for real IP mappings / 真实 IP 映射缓存 TTL
    cache_ttl: "5m"
```

### 各云服务商默认配置

#### 阿里云 (alibaba)

```yaml
cloud:
  provider: "alibaba"
  proxy_protocol:
    enabled: true
    trusted_lb_ranges:
      - "10.0.0.0/8"      # 阿里云内网
      - "100.64.0.0/10"   # SLB 内网
```

#### 腾讯云 (tencent)

```yaml
cloud:
  provider: "tencent"
  proxy_protocol:
    enabled: true
    trusted_lb_ranges:
      - "10.0.0.0/8"      # 腾讯云内网
      - "100.64.0.0/10"   # CLB 内网
```

#### AWS (aws)

```yaml
cloud:
  provider: "aws"
  proxy_protocol:
    enabled: true
    trusted_lb_ranges:
      - "10.0.0.0/8"      # VPC 内网
      - "172.16.0.0/12"   # VPC 内网
```

## 使用方法

### 1. 启用云环境支持

```bash
# 编辑配置文件
sudo vim /etc/netxfw/config.yaml

# 热重载配置
sudo netxfw system reload
```

### 2. 真实 IP 黑名单管理

真实 IP 黑名单通过 API/CLI 管理，不存储在配置文件中：

```bash
# 封禁真实 IP
sudo netxfw cloud block 192.168.1.100 --reason "恶意攻击" --duration "24h"

# 解封 IP
sudo netxfw cloud unblock 192.168.1.100

# 查看黑名单
sudo netxfw cloud blacklist list
```

### 3. 自动封禁

当真实 IP 触发限速规则时，可以自动将其加入黑名单：

```yaml
rate_limit:
  enabled: true
  auto_block: true
  auto_block_expiry: "5m"
```

## 工作原理

### Proxy Protocol 解析流程

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                        Proxy Protocol 解析流程                                │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  1. 连接到达 NetXFW                                                          │
│     └─▶ 源 IP: 10.0.1.100 (LB IP)                                           │
│                                                                              │
│  2. 检查是否来自可信 LB                                                       │
│     └─▶ 10.0.1.100 在 10.0.0.0/8 范围内 → 是可信 LB                          │
│                                                                              │
│  3. 解析 Proxy Protocol 头                                                   │
│     └─▶ PROXY TCP4 192.168.1.100 10.0.1.100 54321 80                        │
│     └─▶ 真实 IP: 192.168.1.100                                              │
│                                                                              │
│  4. 检查真实 IP 黑名单                                                        │
│     └─▶ 192.168.1.100 在黑名单中 → DROP                                      │
│     └─▶ 192.168.1.100 不在黑名单中 → 继续处理                                 │
│                                                                              │
│  5. 缓存真实 IP 映射                                                          │
│     └─▶ 连接 ID → 真实 IP (缓存 TTL: 5m)                                     │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Proxy Protocol 版本

NetXFW 支持两种 Proxy Protocol 版本：

| 版本 | 格式 | 特点 |
|------|------|------|
| V1 | 文本格式 | 可读性好，易于调试 |
| V2 | 二进制格式 | 性能更高，支持更多协议 |

**V1 示例：**
```
PROXY TCP4 192.168.1.100 10.0.1.100 54321 80\r\n
```

**V2 示例：**
```
\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A\x21\x11\x00\x0C\xC0\xA8\x01\x64\x0A\x00\x01\x64\xD4\x31\x00\x50
```

## 黑名单存储

真实 IP 黑名单存储在 `dynamic_blacklist` Map 中，与动态黑名单共享：

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          黑名单存储架构                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────────┐  │
│  │  API/CLI        │     │  RealIP Manager │     │  XDP Map            │  │
│  │  netxfw cloud   │────▶│  AddToBlacklist │────▶│  dynamic_blacklist  │  │
│  │  block/unblock  │     │  (SDK Callback) │     │  (LRU Hash)         │  │
│  └─────────────────┘     └─────────────────┘     └─────────────────────┘  │
│                                                           │                │
│                                                           ▼                │
│                                                  ┌─────────────────────┐  │
│                                                  │  XDP 程序           │  │
│                                                  │  检查真实 IP        │  │
│                                                  │  匹配 → DROP        │  │
│                                                  └─────────────────────┘  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## 注意事项

### 1. 云 LB 配置

确保云服务商的负载均衡器已启用 Proxy Protocol：

**阿里云 SLB：**
```bash
# 在 SLB 控制台开启 Proxy Protocol
# 或使用 API 配置
```

**腾讯云 CLB：**
```bash
# 在 CLB 控制台开启 Proxy Protocol
# 监听器配置 → 高级配置 → 开启 Proxy Protocol
```

**AWS ALB/NLB：**
```bash
# ALB 默认支持 Proxy Protocol v2
# NLB 需要手动开启
aws elbv2 modify-load-balancer-attributes \
  --load-balancer-arn <arn> \
  --attributes Key=proxy_protocol_v2.enabled,Value=true
```

### 2. 性能影响

- Proxy Protocol 解析在用户态进行，对 XDP 性能影响极小
- 真实 IP 缓存机制避免重复解析
- 建议设置合理的缓存 TTL (默认 5 分钟)

### 3. 安全考虑

- 只信任来自可信 LB IP 范围的 Proxy Protocol 头
- 不要将公网 IP 添加到可信范围
- 定期审查黑名单条目

## 故障排查

### 检查配置是否生效

```bash
# 查看系统状态
sudo netxfw system status

# 检查云配置
sudo netxfw cloud config show
```

### 测试 Proxy Protocol 解析

```bash
# 使用演示程序
go run test/demo/cloud_demo.go

# 查看日志
sudo journalctl -u netxfw -f
```

### 常见问题

| 问题 | 原因 | 解决方案 |
|------|------|----------|
| 无法获取真实 IP | LB 未启用 Proxy Protocol | 在云控制台开启 |
| 解析失败 | LB IP 不在可信范围 | 添加到 trusted_lb_ranges |
| 黑名单不生效 | XDP 程序未加载 | 运行 `netxfw system on` |

## 相关文档

- [架构设计](../architecture.md)
- [CLI 命令手册](../cli/cli.md)
- [插件开发指南](../plugins/plugins.md)
