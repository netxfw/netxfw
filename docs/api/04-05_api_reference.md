# netxfw API 文档

## 概述

netxfw 提供了一套完整的 RESTful API，用于管理和控制防火墙规则。API 服务默认运行在 `http://localhost:11811`。

## 认证

大多数 API 端点需要认证。使用 Bearer Token 进行身份验证：

```
Authorization: Bearer <token>
```

## API 端点

### 健康检查

#### 健康检查（Kubernetes 风格）
```
GET /healthz
```
**响应示例**:
```json
{
  "status": "ok"
}
```

#### 详细健康状态
```
GET /health
```
**响应示例**:
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "uptime": "24h"
}
```

#### BPF Map 健康检查
```
GET /health/maps
GET /health/map?name=<map_name>
```

### 版本信息

#### 获取版本
```
GET /version
```
**响应示例**:
```json
{
  "version": "1.0.0",
  "commit": "abc123",
  "build_date": "2024-01-01"
}
```

### 统计信息

#### 获取统计信息
```
GET /api/stats
```
**响应示例**:
```json
{
  "packets": {
    "total": 1234567,
    "passed": 1234000,
    "dropped": 567
  },
  "drop_reasons": {
    "blacklist": 300,
    "rate_limit": 150,
    "port_blocked": 117
  },
  "maps": {
    "blacklist_count": 1234,
    "whitelist_count": 56,
    "conntrack_count": 1500
  }
}
```

### 规则管理

#### 获取所有规则
```
GET /api/rules
```
**响应示例**:
```json
{
  "rules": [
    {
      "ip": "192.168.1.100",
      "port": 80,
      "action": "allow"
    }
  ]
}
```

#### 添加规则
```
POST /api/rules
```
**请求体**:
```json
{
  "ip": "192.168.1.100",
  "port": 80,
  "action": "allow"
}
```

#### 删除规则
```
DELETE /api/rules
```
**请求体**:
```json
{
  "ip": "192.168.1.100",
  "port": 80
}
```

### 配置管理

#### 获取配置
```
GET /api/config
```

#### 更新配置
```
PUT /api/config
```
**请求体**:
```json
{
  "base": {
    "default_deny": true
  }
}
```

### 同步操作

#### 同步状态
```
GET /api/sync
```

#### 同步到 BPF Map
```
POST /api/sync
```
**请求体**:
```json
{
  "action": "to_map"
}
```

### 连接跟踪

#### 获取连接跟踪表
```
GET /api/conntrack
```
**查询参数**:
- `limit`: 最大返回条数（默认: 100）
- `offset`: 分页偏移
- `protocol`: 协议过滤（tcp/udp/icmp）

**响应示例**:
```json
{
  "connections": [
    {
      "src_ip": "192.168.1.100",
      "dst_ip": "8.8.8.8",
      "src_port": 12345,
      "dst_port": 53,
      "protocol": "udp",
      "last_seen": "2024-01-01T00:00:00Z"
    }
  ],
  "total": 1500
}
```

### 性能监控

#### 获取性能统计
```
GET /api/perf
```

#### 获取延迟统计
```
GET /api/perf/latency
```

#### 获取缓存统计
```
GET /api/perf/cache
```

#### 获取流量统计
```
GET /api/perf/traffic
```

#### 重置性能统计
```
POST /api/perf/reset
```

### 指标 API (v1)

#### 获取所有指标
```
GET /api/v1/metrics
```

#### 获取流量指标
```
GET /api/v1/metrics/traffic
```

#### 获取连接跟踪健康状态
```
GET /api/v1/metrics/conntrack
```

#### 获取 Map 使用情况
```
GET /api/v1/metrics/maps
```

#### 获取限速统计
```
GET /api/v1/metrics/ratelimit
```

#### 获取协议统计
```
GET /api/v1/metrics/protocols
```

### Prometheus 指标

#### 获取 Prometheus 格式指标
```
GET /metrics
```

## 错误处理

API 使用标准 HTTP 状态码：

| 状态码 | 说明 |
|--------|------|
| `200 OK` | 请求成功 |
| `201 Created` | 资源已创建 |
| `400 Bad Request` | 请求格式错误 |
| `401 Unauthorized` | 未授权 |
| `404 Not Found` | 资源不存在 |
| `500 Internal Server Error` | 服务器内部错误 |

**错误响应格式**:
```json
{
  "error": "Invalid IP address format",
  "code": "INVALID_IP"
}
```

## 示例

### 使用 curl 添加规则
```bash
curl -X POST http://localhost:11811/api/rules \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{
    "ip": "192.168.1.100",
    "port": 80,
    "action": "allow"
  }'
```

### 使用 curl 获取统计信息
```bash
curl -X GET http://localhost:11811/api/stats \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### 使用 curl 获取连接跟踪
```bash
curl -X GET "http://localhost:11811/api/conntrack?limit=50&protocol=tcp" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### 使用 curl 健康检查
```bash
curl -X GET http://localhost:11811/healthz
```

## 调试端点

当配置中启用 `enable_pprof: true` 时，以下端点可用：

```
GET /debug/pprof/         # pprof 索引
GET /debug/pprof/cmdline  # 命令行
GET /debug/pprof/profile  # CPU profile
GET /debug/pprof/symbol   # 符号表
GET /debug/pprof/trace    # 执行追踪
```

## 相关文档

- [CLI 命令手册](./cli/03-01_cli.md) - 命令行操作
- [配置管理](./07-01_config_management_unification.md) - 配置说明
- [架构概览](./02-01_architecture.md) - 系统架构
