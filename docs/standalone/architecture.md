# 系统架构 (Architecture)

`netxfw` 采用了经典的 "控制面 (Go) + 数据面 (eBPF/XDP)" 架构，并利用 eBPF Map Pinning 实现多进程间的状态共享。

## 版本规划 (Roadmap & Editions)

`netxfw` 规划了以下七个版本，以适应从嵌入式设备到超大规模集群的不同场景：

- **单机版 (Standalone)**: 核心高性能防火墙，支持基础 XDP/eBPF 拦截 and 规则管理。
- **单机 AI 版 (Standalone AI)**: 在单机版基础上集成 TinyML 引擎，支持实时流量异常检测。
- **小集群版 (Small Cluster)**: 支持多节点协同，通过 GitOps 同步策略，适用于 10 台以内服务器。
- **小集群 AI 版 (Small Cluster AI)**: 结合集群管理与 AI 检测能力。
- **大集群版 (Large Cluster)**: 针对成百上千节点优化，支持更复杂的拓扑、分级策略和高性能状态同步。
- **大集群 AI 版 (Large Cluster AI)**: 分布式 AI 检测，支持全局威胁情报共享与联动。
- **嵌入式版 (Embedded)**: 针对 ARM/MIPS 等嵌入式设备优化，极低资源占用，移除 Web UI 等非核心组件。

---

## 核心组件

### 1. 数据面 (Data Plane - eBPF/XDP/TC)
- **模块化设计**：BPF 代码被拆分为核心逻辑 (`modules/`) 和协议处理器 (`protocols/`)，通过 `#include` 组合。
- **插件系统 (Tail Call)**：引入了 `jmp_table` (Prog Array Map)，允许在主程序执行过程中跳转到第三方插件。
- **位置**：运行在内核中，网卡驱动层 (XDP) 和流量控制层 (TC)。
- **职责**：
    - **包过滤**：使用 LPM (Longest Prefix Match) 算法对 IP 和网段进行毫秒级匹配。
    - **有状态追踪 (Conntrack)**：在 XDP 层拦截入站包，在 TC (Egress) 层监控出站包，自动维护双向连接状态。
    - **流量整形 (QoS)**：在 XDP 层直接实现基于令牌桶 (Token Bucket) 算法的限速，支持 per-IP/CIDR 的带宽和 PPS 控制，兼容 IPv4 和 IPv6。
    - **高性能统计**：利用 `Per-CPU Map` 记录 pass/drop 计数，避免原子操作在多核下的性能损耗。

### 2. 安全面 (Security - PKI/mTLS)
- **国密支持 (SM2/SM3)**：支持中国国家密码标准，满足合规性要求。
- **后量子加密 (PQC)**：集成 Ed25519 等抗量子攻击算法，为未来安全做准备。
- **双向认证 (mTLS)**：节点间通信强制进行双向证书校验，防止中间人攻击。

### 3. 控制面 (Control Plane - Go)
- **位置**：用户态。
- **职责**：
    - **加载器**：将 eBPF 程序加载到内核并固定到 `/sys/fs/bpf/netxfw`。
    - **状态迁移 (Migrator)**：在热重载期间，负责将旧 BPF Map 中的连接状态和规则无损迁移到新 Map。
    - **Web/API 服务**：提供可视化管理界面和外部集成接口。
    - **规则持久化**：将用户通过 CLI 添加的动态规则同步到本地 JSON 文件，确保重启不丢失。

---

## 核心流程

### 1. 数据包拦截过滤流程 (Packet Filtering Pipeline)

`netxfw` 的数据面处理遵循严格的分层过滤逻辑，旨在以最快速度剔除恶意流量。

#### 第一阶段：主入口与分发 (Main Entry)
- **配置刷新**: 读取 BPF 全局配置变量（如版本号、开关状态）。
- **插件钩子 (Tail Call)**: 执行用户动态加载的第三方插件（索引 2-15）。
- **协议分发**: 根据以太网协议头跳转至 IPv4 或 IPv6 处理器。

#### 第二阶段：协议级处理 (Protocol Handler)
以 IPv4 为例，处理流程如下：

1. **基础校验 (Sanity & Security)**
    - **Bogon 过滤**: 丢弃来自保留或非法地址段的流量。
    - **分片保护**: 可选丢弃 IP 分片包，防止重组攻击。
    - **TCP 状态校验**: 验证 TCP 标志位组合（如拦截 Null/Xmas 扫描）。
    - **源地址防欺骗**: 丢弃多播/广播作为源地址的非法包。

2. **规则匹配 (Rules Matching)**
    - **白名单 (Whitelist)**: **最高优先级**。匹配成功的流量直接 `XDP_PASS`。
    - **动态黑名单 (Dynamic Lock List)**: 基于 LRU Hash 的高性能单 IP 匹配，用于快速拦截。
    - **静态黑名单 (Static Lock List)**: 基于 LPM Trie 的 CIDR 匹配。
    - **IP 限速 (Rate Limiting)**: 基于令牌桶算法。支持仅对 SYN 包限速以防御 SYN Flood。
    - **自动拦截 (Auto Blocking)**: **新增功能**。当某个 IP 触发限速阈值时，系统可自动将其加入动态黑名单（`dyn_lock_list`），实现毫秒级的快速拦截。支持配置拦截时长，利用 `LRU_HASH` 的特性自动淘汰过期条目。

3. **状态检查 (Stateful Inspection)**
    - **Conntrack 查找**: 查找连接追踪表。如果是已知连接的回包或后续包，直接 `XDP_PASS`。

4. **细粒度控制 (Fine-grained Control)**
    - **IP+Port 规则**: 匹配特定的源 IP 和目标端口组合。
    - **ICMP 限速**: 针对 Ping 流量进行专项限速。

5. **默认策略 (Default Policy)**
    - **端口放行**: 如果开启 `default_deny`，则仅放行在 `allowed_ports` 列表中的端口。
    - **最终动作**: 默认为 `XDP_PASS`。

---

### 有状态连接追踪 (Conntrack)
`netxfw` 维护了一个 `ct_map` (LRU Hash Map)，用于存储 `(SrcIP, DstIP, SrcPort, DstPort, Protocol)` 五元组。
1. **出站**：当主机主动向外发起请求时，TC 挂载点会捕捉到出站包并向 `ct_map` 写入一条状态。
2. **入站**：当回包到达 XDP 时，程序会先查 `ct_map`。如果存在匹配的状态，则直接放行，无需经过复杂的规则检查。

### 无损热重载 (Hot Reload)
当调整配置（如增大 `lock_list` 容量）时：
1. 控制面启动一个新的 BPF 对象。
2. 通过迭代旧 Map 键值对，将其批量迁移到新 Map。
3. 原子地替换网卡上的 XDP 程序。
4. 关闭旧的 BPF 对象，完成无感知更新。

### 插件化执行流 (Tail Call)
`netxfw` 使用 `bpf_tail_call` 实现了可扩展的执行链：
1. **主程序入口 (`xdp_firewall`)**：提取数据包基本信息。
2. **插件跳转**：尝试跳转到 `jmp_table` 的 `PROG_IDX_PLUGIN_START`。如果对应位置有程序，内核将跳转执行。
3. **协议跳转**：根据 `L3` 协议类型，跳转到 `xdp_ipv4` 或 `xdp_ipv6` 处理器进行具体匹配。

---

## 流程图

```text
[ 网络数据包 ]
      |
      v
+-----------------------------+
|    XDP (内核态数据面)        | <----------+
+-----------------------------+            |
| 1. Conntrack 状态检查 (Fast) |            |
| 2. 白名单 LPM 匹配          |            |
| 3. 黑名单 LPM 匹配          |            | [ Map Pinning ]
| 4. IP+Port 规则检查         |            | (/sys/fs/bpf/netxfw/)
| 5. 默认策略 (Allow/Deny)     |            |
+-----------------------------+            |
      |                                    |
      +--- [丢弃] ---> (更新 Per-CPU 计数)  |
      |                                    |
      +--- [通过] ---> (进入内核栈/TC更新)   |
                                           |
      +------------------------------------+
      |
+-----------------------------+
|     Go (用户态控制面)        |
+-----------------------------+
| - State Migrator (热重载)   |
| - Web UI / API (11811)      |
| - Rules Persistence (JSON)  |
+-----------------------------+
```
