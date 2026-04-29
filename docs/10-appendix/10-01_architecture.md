# netxfw 架构设计

## 概览
`netxfw` 是一个基于 **eBPF (Extended Berkeley Packet Filter)** 和 **XDP (eXpress Data Path)** 构建的高性能可编程防火墙。它运行在 Linux 网络栈的最前端（网卡驱动钩子），能够在数据包到达内核网络栈（`sk_buff` 分配）之前，以极低的 CPU 开销丢弃或重定向数据包。

## 整体架构

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              NetXFW 整体架构                                     │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │                           CLI 命令层 (cmd/)                              │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────────┐  │   │
│  │  │  netxfw      │  │ netxfw-agent │  │ netxfw-dp / netxfw-controller│  │   │
│  │  │ (主命令)     │  │ (Agent 进程) │  │ (数据平面进程)               │  │   │
│  │  └──────┬───────┘  └──────┬───────┘  └──────────────┬───────────────┘  │   │
│  └─────────┼─────────────────┼──────────────────────────┼──────────────────┘   │
│            │                 │                          │                       │
│  ┌─────────▼─────────────────▼──────────────────────────▼──────────────────┐   │
│  │                           SDK 层 (pkg/sdk/)                              │   │
│  │  ┌──────────────────────────────────────────────────────────────────┐  │   │
│  │  │  SDK (统一 API 接口)                                              │  │   │
│  │  │  ├── Manager 接口 (黑名单/白名单/限速/连接跟踪...)                │  │   │
│  │  │  ├── Stats 接口 (统计信息)                                        │  │   │
│  │  │  └── Mock (测试模拟)                                              │  │   │
│  │  └──────────────────────────────────────────────────────────────────┘  │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                                      │                                          │
│  ┌───────────────────────────────────▼─────────────────────────────────────┐   │
│  │                数据通路层 (internal/datapath/xdp/)                 │   │
│  │  ┌─────────────────────────────────────────────────────────────────┐   │   │
│  │  │  XDP Manager - eBPF 程序管理                                     │   │   │
│  │  │  ├── 程序加载/卸载/热重载                                        │   │   │
│  │  │  ├── Map 操作 (黑名单/白名单/限速/连接跟踪)                      │   │   │
│  │  │  ├── 统计收集 (PPS/BPS/丢包率)                                   │   │   │
│  │  │  └── 健康检查                                                    │   │   │
│  │  └─────────────────────────────────────────────────────────────────┘   │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                                      │                                          │
│  ┌───────────────────────────────────▼─────────────────────────────────────┐   │
│  │                         服务层 (internal/)                               │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌────────────┐  │   │
│  │  │   api/       │  │   daemon/    │  │   app/       │  │  config/   │  │   │
│  │  │  HTTP API    │  │  守护进程    │  │  应用入口    │  │  配置管理  │  │   │
│  │  │  RESTful     │  │  Agent/DP    │  │  InstallXDP  │  │  Manager   │  │   │
│  │  │  Web UI      │  │  同步/监控   │  │  RemoveXDP   │  │  Loader    │  │   │
│  │  └──────────────┘  └──────────────┘  └──────────────┘  └────────────┘  │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                                      │                                          │
│  ┌───────────────────────────────────▼─────────────────────────────────────┐   │
│  │                         插件层 (internal/plugins/)                       │   │
│  │  ┌──────────────────────────────────────────────────────────────────┐  │   │
│  │  │  plugins/                                                         │  │   │
│  │  │  ├── types/              (插件接口定义)                           │  │   │
│  │  │  ├── registry.go         (插件注册表)                             │  │   │
│  │  │  └── agent/                                                       │  │   │
│  │  │      ├── logengine/      (日志引擎插件)                           │  │   │
│  │  │      ├── metrics/        (指标插件)                               │  │   │
│  │  │      └── web/            (Web UI 插件)                            │  │   │
│  │  └──────────────────────────────────────────────────────────────────┘  │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                                      │                                          │
│  ┌───────────────────────────────────▼─────────────────────────────────────┐   │
│  │                       功能模块层 (internal/)                             │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌────────────┐  │   │
│  │  │ cloudconfig/ │  │  proxyproto/ │  │   realip/    │  │  ppfilter/ │  │   │
│  │  │ 云服务商配置 │  │  PP 协议解析 │  │  真实IP管理  │  │  提取器    │  │   │
│  │  │ 阿里/腾讯/AWS│  │  V1/V2       │  │  黑名单同步  │  │  连接包装  │  │   │
│  │  └──────────────┘  └──────────────┘  └──────────────┘  └────────────┘  │   │
│  │                                                                         │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌────────────┐  │   │
│  │  │   cluster/   │  │   engine/    │  │  optimizer/  │  │  metrics/  │  │   │
│  │  │  集群管理    │  │  TinyML引擎  │  │  规则优化    │  │  指标收集  │  │   │
│  │  │  高可用      │  │  异常检测    │  │  CIDR合并    │  │  Prometheus│  │   │
│  │  └──────────────┘  └──────────────┘  └──────────────┘  └────────────┘  │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                                      │                                          │
│  ┌───────────────────────────────────▼─────────────────────────────────────┐   │
│  │                        工具层 (internal/utils/)                          │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌────────────┐  │   │
│  │  │   logger/    │  │   fmtutil/   │  │   iputil/    │  │  ipmerge/  │  │   │
│  │  │  日志框架    │  │  格式化工具  │  │  IP 工具     │  │  IP 合并   │  │   │
│  │  │  Zap 封装    │  │  数字/时间   │  │  IPv4/IPv6   │  │  CIDR 优化 │  │   │
│  │  └──────────────┘  └──────────────┘  └──────────────┘  └────────────┘  │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                                      │                                          │
│  ┌───────────────────────────────────▼─────────────────────────────────────┐   │
│  │                          eBPF 层 (bpf/)                                  │   │
│  │  ┌──────────────────────────────────────────────────────────────────┐  │   │
│  │  │  XDP 程序 (内核态运行)                                            │  │   │
│  │  │  ├── include/            (公共头文件)                             │  │   │
│  │  │  ├── protocols/          (协议处理: TCP/UDP/ICMP)                 │  │   │
│  │  │  ├── modules/            (功能模块: 过滤/限速/连接跟踪)           │  │   │
│  │  │  └── plugins/            (插件扩展点)                             │  │   │
│  │  └──────────────────────────────────────────────────────────────────┘  │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

## 核心组件

### 1. 数据面 (Data Plane - eBPF/XDP)
数据面由 C 语言编写，编译为 BPF 字节码，直接在内核中运行。
*   **位置**: `bpf/`
*   **核心特性**:
    *   **统一 LPM Trie**: 使用单个 128 位最长前缀匹配 (LPM) Trie 同时处理 IPv4 和 IPv6 流量。IPv4 地址在内部被处理为 IPv4 映射的 IPv6 地址 (`::ffff:a.b.c.d`)。
    *   **无锁设计**: 使用 Per-CPU 数组和哈希表存储统计信息，最大程度减少锁竞争。
    *   **XDP 动作**: 支持 `XDP_DROP` (拦截), `XDP_PASS` (放行), 和 `XDP_TX` (回弹 - 计划中)。
    *   **插件扩展**: 通过 Tail Call 机制支持 14 个插件扩展点（索引 2-15）。

### 2. 控制面 (Control Plane - Go Agent)
控制面由 Go 语言编写，运行在用户空间，负责管理 BPF 程序的生命周期并与 BPF Map 交互。
*   **位置**: `cmd/netxfw`, `internal/`
*   **主要职责**:
    *   **加载/卸载**: 使用 `cilium/ebpf` 库加载 XDP 程序并将 Map 固定 (Pin) 到 `/sys/fs/bpf/netxfw_v2`。
    *   **Map 管理**: 对 BPF Map 进行增删改查操作 (添加/移除规则)。
    *   **持久化**: 将运行时 BPF Map 状态同步到配置与规则持久化文件（以 `config.toml` 为核心入口）。
    *   **CLI**: 提供用户友好的命令行接口 (`netxfw rule add`, `netxfw system status`)。

---

## 架构层次（2026-04 更新）

NetXFW 采用**领域驱动设计（DDD）**和**六边形架构**，清晰地划分了各个层次：

```
┌─────────────────────────────────────────────────────────────┐
│                   用户接口层 (Interfaces)                    │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │   CLI       │  │  REST API   │  │   Web UI    │         │
│  │  (cmd/)     │  │ (internal/) │  │ (plugins/)  │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                   应用服务层 (Application)                   │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │  规则服务   │  │  配置服务   │  │  插件服务   │         │
│  │  (app/rule) │  │ (app/config)│  │(app/plugin) │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                    领域层 (Domain)                           │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │  规则模型   │  │  配置模型   │  │  插件模型   │         │
│  │(domain/rule)│  │(domain/config)│(domain/plugin)│        │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │  运行时模型 │  │  系统模型   │  │  错误定义   │         │
│  │(domain/runtime)│(domain/system)│(domain/errors)│        │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                  基础设施层 (Infrastructure)                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │  XDP 数据面  │  │  配置持久化 │  │  HTTP 服务   │         │
│  │(datapath/)  │  │(adapters/)  │  │   (api/)    │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
└─────────────────────────────────────────────────────────────┘
```

### 层次说明

1. **用户接口层 (Interfaces)**
   - CLI 命令行接口 (`cmd/`)
   - REST API HTTP 接口 (`internal/api/`)
   - Web UI 插件 (`internal/plugins/webplugin/`)
   - 负责接收用户请求，转换为领域操作

2. **应用服务层 (Application)**
   - 规则服务 (`internal/app/rule/`)
   - 配置服务 (`internal/app/config/`)
   - 插件服务 (`internal/app/plugin/`)
   - 协调领域对象，实现业务流程

3. **领域层 (Domain)** - **核心业务逻辑**
   - 规则模型 (`internal/domain/rule/`)
   - 配置模型 (`internal/domain/config/`)
   - 插件模型 (`internal/domain/plugin/`)
   - 运行时模型 (`internal/domain/runtime/`)
   - 系统模型 (`internal/domain/system/`)
   - 错误定义 (`internal/domain/errors/`)
   - **纯 Go 实现，无外部依赖**

4. **基础设施层 (Infrastructure)**
   - XDP 数据面 (`internal/datapath/xdp/`)
   - 配置持久化 (`internal/adapters/configfile/`)
   - HTTP 服务 (`internal/api/`)
   - 插件运行时 (`internal/adapters/plugins/`)
   - 实现技术细节，依赖领域层定义

### 数据通路细粒度分包

`internal/datapath/xdp/` 采用细粒度分包设计，每个子包职责单一：

| 子包 | 职责 | 关键文件 |
|------|------|----------|
| `backend/` | 后端实现（Manager/Adapter/同步/统计） | `xdp_manager.go`, `adapter.go`, `sync.go` |
| `lifecycle/` | XDP 程序生命周期管理 | `install.go`, `attach.go`, `reload.go` |
| `maps/` | BPF Map 访问和包装 | `maintenance.go`, `config_indexes.go` |
| `programs/` | 程序加载和跳转表 | `load.go`, `manager.go` |
| `plugins/` | 插件集成 | `loader.go`, `slots.go` |
| `stats/` | 统计信息收集 | `collector.go`, `performance.go` |
| `health/` | 健康检查 | `status.go` |
| `sync/` | 同步机制 | `incremental.go`, `reconcile.go` |

这种设计提高了代码的可维护性和可测试性。

### backend 子包详解

`internal/datapath/xdp/backend/` 是 XDP 数据通路的核心实现：

| 文件 | 功能 |
|------|------|
| `xdp_manager.go` | XDP Manager 核心实现 |
| `adapter.go` | 适配器，实现端口接口 |
| `sync.go` | 配置同步机制 |
| `xdp_stats.go` | 统计信息收集 |
| `health_check.go` | 健康检查实现 |
| `lifecycle_*.go` | 生命周期管理（XDP/模块/插件） |
| `map_helpers.go` | BPF Map 操作辅助函数 |
| `mock_manager.go` | Mock 实现（测试用） |

### 领域驱动设计（DDD）

NetXFW 采用领域驱动设计，将业务逻辑清晰地组织在领域层：

| 领域 | 职责 | 关键文件 |
|------|------|----------|
| `domain/rule/` | 规则领域模型 | `rule.go`, `validator.go`, `repository.go` |
| `domain/config/` | 配置领域模型 | `config.go`, `loader.go` |
| `domain/plugin/` | 插件领域模型 | `plugin.go`, `registry.go` |
| `domain/runtime/` | 运行时领域模型 | `runtime.go`, `state.go` |
| `domain/system/` | 系统领域模型 | `system.go`, `health.go` |
| `domain/errors/` | 领域错误定义 | `errors.go` |

### 适配器模式

`internal/adapters/` 实现了六边形架构的适配器层：

| 适配器 | 职责 | 关键文件 |
|--------|------|----------|
| `adapters/configfile/` | 配置文件适配器 | `loader.go`, `saver.go`, `restorer.go` |
| `adapters/datapath/` | 数据平面适配器 | `manager.go`, `operations.go` |
| `adapters/plugins/` | 插件运行时适配器 | `runtime.go`, `loader.go` |

### 应用服务层

`internal/app/` 实现应用服务：

| 服务 | 职责 | 关键文件 |
|------|------|----------|
| `app/config/` | 配置管理 | `executor.go`, `planner.go`, `reconcile.go` |
| `app/plugin/` | 插件管理 | `command.go`, `health.go`, `status.go` |
| `app/rule/` | 规则管理 | `add_rule.go`, `remove_rule.go`, `list_rules.go` |

### 辅助模块

| 模块 | 职责 | 关键文件 |
|------|------|----------|
| `internal/errors/` | 统一错误处理 | `unified.go` |
| `internal/i18n/` | 国际化消息 | `messages.go` |
| `internal/binary/` | 二进制协议处理 | `format.go` |

## 目录结构

### 完整目录结构（2026-04 更新）

```
netxfw/
├── bpf/                          # eBPF 程序源码（C 语言）
│   ├── include/                  # 公共头文件
│   ├── protocols/                # 协议处理模块（TCP/UDP/ICMP）
│   ├── modules/                  # 功能模块（过滤/限速/连接跟踪）
│   ├── plugins/                  # 插件扩展点（Tail Call）
│   ├── netxfw.bpf.c              # 主 XDP 程序
│   └── wrappers.bpf.c            # 辅助包装函数
│
├── cmd/                          # 命令行入口
│   ├── agent/                    # Agent 命令实现（rule, limit, system 等）
│   ├── common/                   # 共享工具函数
│   ├── dp/                       # 数据平面命令（conntrack）
│   ├── netxfw/                   # 主命令入口
│   ├── netxfwagent/              # Agent 进程入口（兼容）
│   └── netxfwdp/                 # 数据平面进程入口
│
├── pkg/                          # 公共包（可复用库）
│   ├── configvalidate/           # 配置验证包
│   ├── errors/                   # 错误定义包
│   ├── sdk/                      # SDK 接口（统一 API）
│   │   ├── mock/                 # Mock 实现（测试）
│   │   ├── api.go                # API 定义
│   │   ├── rule.go               # 规则 API
│   │   ├── blacklist.go          # 黑名单 API
│   │   ├── whitelist.go          # 白名单 API
│   │   ├── stats.go              # 统计 API
│   │   ├── health.go             # 健康检查 API
│   │   └── types.go              # 类型定义
│   └── storage/                  # 存储抽象
│
├── internal/                     # 内部实现（私有包）
│   ├── adapters/                 # 适配器层（端口适配）
│   │   ├── configfile/           # 配置文件适配器（加载/保存/恢复）
│   │   ├── datapath/             # 数据平面适配器
│   │   └── plugins/              # 插件运行时适配器
│   │
│   ├── api/                      # HTTP API 服务
│   │   ├── server.go             # API 服务器
│   │   ├── handlers.go           # 请求处理
│   │   ├── handlers_rules.go     # 规则处理
│   │   ├── handlers_metrics.go   # 指标处理
│   │   ├── handlers_health.go    # 健康检查处理
│   │   ├── auth.go               # JWT 认证
│   │   └── ui.go                 # Web UI
│   │
│   ├── app/                      # 应用层（业务逻辑组织）
│   │   ├── config/               # 配置管理
│   │   ├── plugin/               # 插件管理
│   │   └── rule/                 # 规则管理
│   │
│   ├── binary/                   # 二进制协议处理
│   ├── cloudconfig/              # 云服务商配置
│   │
│   ├── daemon/                   # 守护进程
│   │   ├── engine/               # 守护引擎（基础策略/限速/端口/连接跟踪）
│   │   ├── check.go              # 检查函数
│   │   └── runtime_plan.go       # 运行时计划
│   │
│   ├── datapath/                 # 数据通路层
│   │   └── xdp/                  # XDP 数据通路（细粒度分包）
│   │       ├── backend/          # 后端实现（Manager/Adapter/同步/统计）
│   │       ├── lifecycle/        # 生命周期管理（安装/卸载/重载）
│   │       ├── maps/             # BPF Map 操作（访问/包装）
│   │       ├── programs/         # 程序加载（对象加载/跳转表）
│   │       ├── plugins/          # 插件集成（Tail Call 集成）
│   │       ├── stats/            # 统计信息收集
│   │       ├── health/           # 健康检查
│   │       └── sync/             # 同步机制
│   │
│   ├── domain/                   # 领域模型层（DDD）
│   │   ├── config/               # 配置领域模型
│   │   ├── errors/               # 领域错误定义
│   │   ├── plugin/               # 插件领域模型
│   │   ├── rule/                 # 规则领域模型
│   │   ├── runtime/              # 运行时领域模型
│   │   └── system/               # 系统领域模型
│   │
│   ├── engine/                   # TinyML 引擎（异常检测）
│   ├── errors/                   # 统一错误处理
│   ├── i18n/                     # 国际化消息
│   │
│   ├── metrics/                  # 指标系统
│   │   └── exporter/             # Prometheus 导出器
│   │
│   ├── optimizer/                # 规则优化（CIDR 合并）
│   ├── plugins/                  # 插件系统
│   │   ├── logengine/            # 日志引擎插件
│   │   ├── metricsplugin/        # 指标插件
│   │   └── webplugin/            # Web UI 插件
│   │
│   ├── ports/                    # 端口管理
│   ├── ppfilter/                 # Proxy Protocol 过滤器
│   ├── proxyproto/               # Proxy Protocol 解析
│   ├── realip/                   # 真实 IP 管理
│   ├── runtime/                  # 运行时状态
│   ├── utils/                    # 工具函数
│   │   ├── fileutil/             # 文件工具
│   │   ├── fmtutil/              # 格式化工具
│   │   ├── ipmerge/              # IP 合并工具
│   │   ├── iputil/               # IP 工具
│   │   ├── logger/               # 日志框架（Zap）
│   │   └── xdputil/              # XDP 工具（接口检测）
│   │
│   └── version/                  # 版本信息
│
├── config/                       # 配置文件示例
├── docs/                         # 文档
├── test/                         # 测试
│   ├── unit/                     # 单元测试
│   ├── integration/              # 集成测试
│   └── logengine/                # 日志引擎专项测试
│
├── tools/                        # 工具程序
│   └── yaml2toml/                # YAML 转 TOML 工具
│
├── Makefile                      # 构建脚本
├── go.mod                        # Go 模块定义
└── config.toml                   # 默认配置文件
```
│   │
│   ├── api/                      # HTTP API
│   │   ├── server.go             # API 服务器
│   │   ├── handlers.go           # 请求处理
│   │   ├── auth.go               # JWT 认证
│   │   └── ui.go                 # Web UI
│   │
│   ├── daemon/                   # 守护进程
│   │   ├── agent.go              # Agent 模式
│   │   ├── dp.go                 # DP 模式
│   │   └── standalone.go         # 单机模式
│   │
│   ├── app/                      # 应用入口
│   │   └── ops.go                # InstallXDP, RemoveXDP, ReloadXDP
│   │
│   ├── config/                   # 配置管理
│   │   ├── manager.go            # 配置管理器
│   │   └── constants.go          # 常量定义
│   │
│   ├── core/engine/              # 核心引擎模块
│   │   ├── base.go               # 基础策略模块
│   │   ├── conntrack.go          # 连接跟踪模块
│   │   ├── port.go               # 端口管理模块
│   │   └── ratelimit.go          # 限速模块
│   │
│   ├── plugins/                  # 插件系统
│   │   ├── types/                # 插件类型定义
│   │   ├── registry.go           # 插件注册表
│   │   └── agent/
│   │       ├── logengine/        # 日志引擎插件
│   │       ├── metrics/          # 指标收集插件
│   │       └── web/              # Web UI 插件
│   │
│   ├── cloudconfig/              # 云服务商配置
│   ├── proxyproto/               # Proxy Protocol 解析
│   ├── realip/                   # 真实 IP 管理
│   ├── ppfilter/                 # 连接过滤器
│   ├── cluster/                  # 集群管理
│   ├── engine/                   # TinyML 引擎
│   ├── optimizer/                # 规则优化
│   ├── metrics/                  # 指标系统
│   ├── runtime/                  # 运行时状态
│   ├── version/                  # 版本信息
│   │
│   └── utils/                    # 工具函数
│       ├── logger/               # 日志框架 (Zap)
│       ├── fmtutil/              # 格式化工具
│       ├── iputil/               # IP 工具
│       ├── ipmerge/              # IP 合并
│       └── fileutil/             # 文件工具
│
├── config/                       # 配置文件示例
├── docs/                         # 文档
├── test/                         # 测试
│   ├── unit/                     # 单元测试
│   ├── integration/              # 集成测试
│   ├── demo/                     # 演示程序
│   └── log-engine/               # 日志引擎测试
│
└── scripts/                      # 脚本
```

## 公共包说明 (pkg/)

`pkg/` 目录包含可复用的公共包，可被外部项目引用：

### pkg/configvalidate/ - 配置验证包

配置验证包提供配置验证相关的通用工具函数：

| 文件 | 功能 |
|------|------|
| `configvalidate.go` | 配置验证器，验证配置项的有效性 |

**使用场景**：
- 外部工具需要验证 netxfw 配置
- 配置迁移和转换工具
- 配置预检查

### pkg/errors/ - 错误定义包

错误定义包提供统一的错误类型和错误处理：

| 文件 | 功能 |
|------|------|
| `errors.go` | 基础错误类型定义 |
| `codes.go` | 错误码定义 |
| `wrapper.go` | 错误包装工具 |

**错误类型**：
```go
// 常见错误类型
var (
    ErrRuleNotFound    = errors.New("rule not found")
    ErrInvalidIP       = errors.New("invalid IP address")
    ErrMapOperation    = errors.New("BPF map operation failed")
    ErrConfigLoad      = errors.New("failed to load config")
)
```

### pkg/sdk/ - SDK 接口

SDK 接口提供统一的 API 抽象，详见 [09-04_sdk_api.md](09-api-reference/09-04_sdk_api.md)。

### pkg/storage/ - 存储抽象

存储抽象提供键值存储接口，支持多种后端：
- 本地文件存储
- etcd 存储（集群模式）
- 内存存储（测试用）

---

## 统一双栈架构
为了简化维护并减少内存占用，`netxfw` 采用了统一 Map 策略：
*   **Map**: `lock_list` (LPM Trie)
*   **Key**: `struct lpm_key` (128 位 IPv6 地址 + 前缀长度)
*   **IPv4 处理**:
    *   用户输入: `192.0.2.1`
    *   内部转换: `::ffff:192.0.2.1`
    *   存储: 存入 128 位 Trie 中。
    *   查找: 进入的 IPv4 数据包在查找前会被构造为 IPv4 映射的 IPv6 Key。

## 数据流向

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                              数据包处理流程                                   │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────┐                                                             │
│  │ 网卡接收    │                                                             │
│  │ 数据包      │                                                             │
│  └──────┬──────┘                                                             │
│         │                                                                    │
│         ▼                                                                    │
│  ┌─────────────────────────────────────────────────────────────────────────┐ │
│  │                        XDP 钩子 (内核态)                                │ │
│  │                                                                         │ │
│  │   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐                │ │
│  │   │  以太网解析  │───▶│  IP 层解析  │───▶│  L4 层解析  │                │ │
│  │   └─────────────┘    └─────────────┘    └─────────────┘                │ │
│  │                                                │                        │ │
│  │                                                ▼                        │ │
│  │   ┌─────────────────────────────────────────────────────────────────┐  │ │
│  │   │                        规则匹配                                  │  │ │
│  │   │                                                                 │  │ │
│  │   │   1. 检查白名单 (whitelist)      ──▶ 匹配 → XDP_PASS           │  │ │
│  │   │   2. 检查黑名单 (lock_list)      ──▶ 匹配 → XDP_DROP           │  │ │
│  │   │   3. 检查动态黑名单 (dynamic)    ──▶ 匹配 → XDP_DROP           │  │ │
│  │   │   4. 检查 IP+端口规则            ──▶ 匹配 → 执行动作           │  │ │
│  │   │   5. 检查限速规则 (rate_limit)   ──▶ 超限 → XDP_DROP           │  │ │
│  │   │   6. 检查连接跟踪 (conntrack)    ──▶ 已建立 → XDP_PASS         │  │ │
│  │   │   7. 默认策略                    ──▶ 根据配置决定              │  │ │
│  │   │                                                                 │  │ │
│  │   └─────────────────────────────────────────────────────────────────┘  │ │
│  │                                                                         │ │
│  └─────────────────────────────────────────────────────────────────────────┘ │
│         │                                                                    │
│         ▼                                                                    │
│  ┌─────────────┐     ┌─────────────┐                                        │
│  │ XDP_DROP    │     │ XDP_PASS    │                                        │
│  │ (丢弃)      │     │ (放行)      │                                        │
│  └─────────────┘     └──────┬──────┘                                        │
│                             │                                                │
│                             ▼                                                │
│                      ┌─────────────┐                                         │
│                      │ 内核网络栈  │                                         │
│                      └─────────────┘                                         │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

## 持久化模型
*   **运行时**: `/sys/fs/bpf/netxfw_v2/*` (固定的 BPF Maps)
*   **存储**: `config.toml` 与规则持久化文件（路径由配置项定义）
*   **同步**: `netxfw system sync` 命令负责运行时状态与存储之间的双向同步

## 运行模式

### 单机模式 (Standalone)
```bash
# 加载 XDP 程序
netxfw system on eth0

# 启动守护进程 (指标收集 + 规则同步)
netxfw system daemon
```

### Agent/DP 模式 (分布式)
```bash
# 数据平面 (XDP 程序)
netxfw-dp --mode dp

# 控制平面 (API + 管理)
netxfw-agent --mode agent
```

## BPF Map 类型

| Map 名称 | 类型 | 用途 |
|----------|------|------|
| `lock_list` | LPM Trie | 静态黑名单 (CIDR) |
| `dynamic_blacklist` | LRU Hash | 动态黑名单 (单 IP) |
| `whitelist` | LPM Trie | 白名单 (CIDR) |
| `conntrack` | Hash | 连接跟踪表 |
| `rate_limit` | Hash | 限速规则 |
| `ip_port_rules` | Hash | IP+端口规则 |
| `stats` | Per-CPU Array | 统计信息 |
| `drop_details` | Per-CPU Hash | 丢包详情 |
| `pass_details` | Per-CPU Hash | 通过详情 |

## 插件架构

```go
// Plugin interface / 插件接口
type Plugin interface {
    Name() string
    Init(ctx *PluginContext) error
    Start(ctx *PluginContext) error
    Stop(ctx *PluginContext) error
    Reload(ctx *PluginContext) error
}
```

### 内置插件

| 插件 | 位置 | 功能 |
|------|------|------|
| **LogEngine** | `plugins/agent/logengine/` | 流量日志、规则匹配 |
| **Metrics** | `plugins/agent/metrics/` | Prometheus 指标 |
| **Web** | `plugins/agent/web/` | Web 管理界面 |

## 云环境支持

NetXFW 支持在云服务商负载均衡器环境下获取真实客户端 IP：

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   客户端    │────▶│   云 LB     │────▶│   NetXFW    │
│  真实 IP    │     │  Proxy Proto│     │  解析真实IP │
└─────────────┘     └─────────────┘     └─────────────┘
```

支持的云服务商：
- 阿里云
- 腾讯云
- AWS (aws)
- Azure (azure)
- GCP (gcp)
- 其他

详见 [云环境真实 IP 获取文档](../05-advanced-features/05-01_realip.md)。
