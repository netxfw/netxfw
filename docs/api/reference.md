# netxfw API 文档

## 概述

netxfw 提供了一套完整的RESTful API，用于管理和控制防火墙规则。API服务默认运行在 `http://localhost:11818/api`。

## 认证

大多数API端点需要认证。使用Bearer Token进行身份验证：

```
Authorization: Bearer <token>
```

## API端点

### 规则管理

#### 获取所有规则
```
GET /rules
```
**响应示例**:
```json
{
  "rules": [
    {
      "ip": "192.168.1.100",
      "port": 80,
      "action": "allow",
      "reason": "Web server access",
      "created_at": "2024-01-01T00:00:00Z"
    }
  ]
}
```

#### 添加规则
```
POST /rules
```
**请求体**:
```json
{
  "ip": "192.168.1.100",
  "port": 80,
  "action": "allow",
  "reason": "Web server access"
}
```

#### 删除规则
```
DELETE /rules
```
**请求体**:
```json
{
  "ip": "192.168.1.100",
  "port": 80
}
```

### 危机规则管理 (Crisis Rules)

#### 添加危机规则
```
POST /rules/crisis
```
**请求体**:
```json
{
  "ip": "10.0.0.1",
  "reason": "Immediate threat",
  "auto_active": true
}
```

### 黑名单管理

#### 添加到黑名单
```
POST /blacklist
```
**请求体**:
```json
{
  "ip": "1.2.3.4",
  "reason": "Malicious activity",
  "duration": 3600
}
```

#### 从黑名单移除
```
DELETE /blacklist
```
**请求体**:
```json
{
  "ip": "1.2.3.4"
}
```

### 统计信息

#### 获取统计信息
```
GET /stats
```
**响应示例**:
```json
{
  "packets_processed": 1234567,
  "packets_allowed": 1234000,
  "packets_blocked": 567,
  "active_rules": 25,
  "uptime_seconds": 86400
}
```

#### 获取连接跟踪表
```
GET /conntrack
```
**响应示例**:
```json
{
  "connections": [
    {
      "src_ip": "192.168.1.100",
      "dst_ip": "8.8.8.8",
      "src_port": 12345,
      "dst_port": 53,
      "protocol": "UDP",
      "state": "ESTABLISHED",
      "last_seen": "2024-01-01T00:00:00Z"
    }
  ]
}
```

### 系统管理

#### 重载配置
```
POST /reload
```
**请求体**:
```json
{
  "force": false
}
```

#### 获取系统健康状态
```
GET /health
```
**响应示例**:
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "bpf_loaded": true,
  "xdp_attached": true
}
```

## 错误处理

API使用标准HTTP状态码：

- `200 OK` - 请求成功
- `201 Created` - 资源已创建
- `400 Bad Request` - 请求格式错误
- `401 Unauthorized` - 未授权
- `404 Not Found` - 资源不存在
- `500 Internal Server Error` - 服务器内部错误

## 示例

### 使用curl添加规则
```bash
curl -X POST http://localhost:11818/api/rules \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{
    "ip": "192.168.1.100",
    "port": 80,
    "action": "allow",
    "reason": "Web server access"
  }'
```

### 使用curl获取统计信息
```bash
curl -X GET http://localhost:11818/api/stats \
  -H "Authorization: Bearer YOUR_TOKEN"
```