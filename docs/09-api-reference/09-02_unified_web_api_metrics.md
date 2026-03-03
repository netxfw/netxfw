# NetXFW - Unified Web, API and Metrics Service

NetXFW 提供了一个统一的服务，将 Web 界面、API 接口和指标监控融合在一个单一的服务中。

## 架构概述

### 统一服务设计
- **Web UI**: 提供直观的 Web 界面，通过根路径 `/` 访问
- **API 接口**: 提供 RESTful API 接口，通过 `/api/*` 路径访问
- **Metrics 监控**: 提供 Prometheus 指标，通过 `/metrics` 路径访问

### 路由结构
```
GET    /                    -> Web UI
GET    /api/stats          -> 统计信息
GET    /api/rules          -> 规则管理
GET    /api/config         -> 配置管理
GET    /api/sync           -> 同步操作
GET    /api/conntrack      -> 连接跟踪
GET    /metrics            -> Prometheus 指标
```

### 配置选项

在 `config.yaml` 中，可以通过以下配置控制服务行为：

```yaml
web:
  enabled: true
  port: 11811
  token: "auto-generated"  # 自动生成或手动指定

metrics:
  enabled: true           # 是否启用指标收集
  server_enabled: false   # 如果为 false，在 Web 服务器上提供指标
  port: 11812             # 独立指标服务器端口
```

当 `metrics.server_enabled` 为 `false` 时，指标将在 Web 服务器的 `/metrics` 路径上提供。
当 `metrics.server_enabled` 为 `true` 时，指标将在独立的服务器上提供。

## 功能特性

### Web 界面
- 实时监控网络流量
- 配置管理界面
- 规则管理界面
- 系统状态概览

### API 接口
- 统计信息查询
- 动态规则管理
- 配置更新
- 系统控制

### 指标监控
- XDP 丢包/通过统计
- 锁定 IP 数量
- 连接跟踪条目数
- 各类规则数量统计

## 部署模式

### 单一服务模式（推荐）
- Web、API 和 Metrics 运行在同一个端口上
- 通过不同的路径进行访问
- 简化部署和管理

### 分离服务模式
- Web 和 API 在一个端口上运行
- Metrics 在独立端口上运行
- 适用于需要独立监控服务的场景