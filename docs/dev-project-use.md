# Netxfw 开发与架构指南：如何定位与使用文档

> **注意**：本文档引用的 `project_architecture_diagrams.md` 文件尚未创建。

本指南旨在帮助开发人员与系统维护人员了解新版 [project_architecture_diagrams.md](project_architecture_diagrams.md) 报告与 `docs/` 目录下现有系统架构及流程文档的关系与映射，从而在日常开发、排查故障时能够快速定位目标代码与设计决策。

---

## 一、 核心定位与视角差异

不同的文档服务于不同的开发目的，它们在视角、解决问题以及呈现形式上存在明显的互补性：

| 维度 | [project_architecture_diagrams.md](project_architecture_diagrams.md) | `docs/` 下的架构与流程文档 |
| :--- | :--- | :--- |
| **主攻视角** | **动态执行与代码实现级视角** (Runtime & Code-level) | **系统设计与架构规范级视角** (System Design & DDD Spec) |
| **主要解决** | 具体的函数调用关系、服务启动时序以及底层的代码级级联位置。 | 静态的模块职责划分、六边形接口规范、DDD 领域层划分及 BPF Map 结构定义。 |
| **展现形式** | Mermaid 流程图、Emerald Professional (翡翠风格 - Style 7) 高对比度调用图、带源码行号的代码级联导航。 | ASCII 字符拓扑图、分包设计表格、详细的内核态数据包过滤阶段描述 (Phase 0 - 7)。 |

---

## 二、 核心流程与文档的对齐分析

### 2.1 数据面与控制面的启动/热重载流程
* **在 [project_architecture_diagrams.md](project_architecture_diagrams.md) 中**：
  * 第一部分使用 **Mermaid 流程图** 详细拆解了数据面 (`netxfwdp`) 与控制面代理 (`netxfwagent`) 的启动生命周期（如 `BootstrapDaemon`、`LoadOrCreateManager`、`ReconcileInterfaces`、`StartCoreModules` 等阶段）。
* **在 `docs/` 下的文档中**：
  * 对齐了 [10-01_architecture.md](10-appendix/10-01_architecture.md) 中的**数据通路细粒度分包**设计（详细描述了 `lifecycle/`、`backend/`、`maps/` 等子包的各自职责）。
  * 对齐了 [10-02_architecture_diagrams.md](10-appendix/10-02_architecture_diagrams.md) 中的**配置热重载流程 (Hot Reload Flow)**，阐述了用户空间 `ConfigCache` 在配置发生容量变化或增量重载时，如何通过 `Migrator` 完成 Map 数据的迭代复制与 Link 更新，进而实现无缝原子替换。

### 2.2 网卡挂载与卸载 (Attach/Detach) 流程
* **在 [project_architecture_diagrams.md](project_architecture_diagrams.md) 中**：
  * 第三部分第 2 点以**代码级函数调用链**的形式串联了网卡挂载的底层实现机制 ([lifecycle_xdp.go](../internal/datapath/xdp/backend/lifecycle_xdp.go))：
    1. **原子热更新**：通过 `link.LoadPinnedLink` 检测现有 Link，调用 `Update` 热替换字节码。
    2. **多模式后备挂载**：依次尝试 `Offload` (硬件卸载) -> `Native` (驱动模式) -> `Generic` (通用模式) 进行挂载，并调用 `Pin` 持久化。
    3. **TC (Traffic Control) 挂载**：调用 `link.AttachTCX` 将 `TcEgress` 程序挂载至 egress 方向支持出站连接跟踪。
* **在 `docs/` 下的文档中**：
  * 对应 [10-01_architecture.md](10-appendix/10-01_architecture.md) 的 **基础设施层** 设计与模块划分，同时对应 [10-02_architecture_diagrams.md](10-appendix/10-02_architecture_diagrams.md) 中关于 TC 挂载及 `ct_map` 连接跟踪流程的静态图示。

### 2.3 安全策略规则同步流程 (Sync)
* **在 [project_architecture_diagrams.md](project_architecture_diagrams.md) 中**：
  * 第三部分第 3 点展示了同步阶段的底层函数级流程以 `PortModule` 模块为例 ([port.go](../internal/daemon/engine/port.go))：
    1. **拉取**：调用 `m.rule.List` 从活跃 BPF Map 中拉取旧规则。
    2. **计算差值并清理**：与期望配置计算差集，调用 `m.rule.RemoveIPPortRule` 删除冗余映射。
    3. **同步写入**：遍历最新策略集，调用 `m.rule.AddIPPortRule` 将新规则写入内核。
* **In `docs/` 下的文档中**：
  * 该流程是 [10-01_architecture.md](10-appendix/10-01_architecture.md) 中**服务层/应用服务层/控制面**管理 eBPF Map 与本地配置文件之间双向数据一致性的逻辑延伸。

---

## 三、 对内核态数据包过滤流程的互补关系

* [10-03_packet_filter_flow.md](10-appendix/10-03_packet_filter_flow.md) 详细描述了在内核中 XDP 钩子（`xdp_firewall`）处理数据包时的 **8 个逻辑阶段** (Phase 0 - 7，包括 Bogon 过滤、白名单放行、动态/静态黑名单匹配、IP 限速、连接跟踪、IP+Port 精细化控制及默认策略)。
* [project_architecture_diagrams.md](project_architecture_diagrams.md) 从 **用户态控制流** 的角度进行了补充，说明了：
  - 上述过滤阶段所需的全局缓存配置（如 `cached_default_deny`）是如何在用户空间初始化并按采样周期（每 1000 个数据包）同步更新的。
  - 核心过滤阶段依赖的 BPF Maps（如 `lock_list`、`whitelist`、`ip_port_rules`）在用户空间是通过何种增量机制进行更新与热修复的。

---

## 四、 完整的映射与索引对照表

为了方便您在开发和调试时在“架构设计图”、“流程文档”与“代码实现”三者之间快速跳转，可以参考下表：

| 业务/系统流程 | docs/ 对应文档章节 | project_architecture_diagrams.md 位置 | 核心 Go 源码 / 实现位置 |
| :--- | :--- | :--- | :--- |
| **系统分层架构 (DDD)** | [10-01_architecture.md:L125-198](10-appendix/10-01_architecture.md#L125-L198) | *N/A (专攻动态流)* | 整个 `internal/` 目录结构划分 |
| **数据面启动与 eBPF 加载** | [10-01_architecture.md:L200-215](10-appendix/10-01_architecture.md#L200-L215) | Section 一.1 (Mermaid) & 三.1 (NewManager 步骤) | [xdp_manager.go](../internal/datapath/xdp/backend/xdp_manager.go) |
| **网卡接口挂载 (XDP/TC)** | [10-02_architecture_diagrams.md:L63-69](10-appendix/10-02_architecture_diagrams.md#L63-L69) | Section 一.1 第 6 步 & 三.2 (Attach 步骤) | [lifecycle_xdp.go](../internal/datapath/xdp/backend/lifecycle_xdp.go) |
| **规则下发与 Map 同步** | [10-02_architecture_diagrams.md:L232-306](10-appendix/10-02_architecture_diagrams.md#L232-L306) | Section 二 (Port 同步调用图) & 三.3 (Sync 步骤) | [port.go](../internal/daemon/engine/port.go) |
| **数据包过滤核心逻辑** | [10-03_packet_filter_flow.md](10-appendix/10-03_packet_filter_flow.md) & [10-04_summary_packet_filter.md](10-appendix/10-04_summary_packet_filter.md) | *N/A (此图专注用户态交互)* | [netxfw.bpf.c](../bpf/netxfw.bpf.c) (内核态过滤入口) |

---

## 五、 总结建议

> [!TIP]
> **什么时候阅读系统设计架构文档 (`docs/`) ？**
> 当您需要修改业务逻辑、添加新的扩展模块或调整基础配置参数时，应优先阅读 [10-01_architecture.md](10-appendix/10-01_architecture.md)，确保您的修改符合 DDD（领域驱动设计）与六边形架构的分层设计。

> [!IMPORTANT]
> **什么时候参考核心流程报告 ([project_architecture_diagrams.md](project_architecture_diagrams.md)) ？**
> 当您需要优化 eBPF 的资源加载、修复网卡挂载异常、或者调试规则增量下发的同步性能时，应参考此报告提供的动态调用链路，并直接跳转至对应的具体代码行进行断点调试或代码重构。