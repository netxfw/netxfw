# Netxfw Development & Architecture Guide: How to Locate and Use Documentation

This guide helps developers and system maintainers understand the relationship and mapping between the [project_architecture_diagrams.md](project_architecture_diagrams.md) report and the existing system architecture and process documentation in the `docs/` directory, enabling quick navigation to target code and design decisions during daily development and troubleshooting.

---

## 1. Core Positioning & Perspective Differences

Different documents serve different development purposes. They have clear complementary differences in perspective, problem-solving, and presentation:

| Dimension | [project_architecture_diagrams.md](project_architecture_diagrams.md) | `docs/` Architecture & Process Documents |
| :--- | :--- | :--- |
| **Primary Perspective** | **Dynamic execution & code implementation level** (Runtime & Code-level) | **System design & architecture specification level** (System Design & DDD Spec) |
| **Main Focus** | Specific function call relationships, service startup sequences, and underlying code-level cascade locations | Static module responsibility division, hexagonal interface specifications, DDD domain layer partitioning, and BPF Map structure definitions |
| **Presentation** | Mermaid flowcharts, Emerald Professional (Style 7) high-contrast call graphs, code cascade navigation with source line numbers | ASCII character topology diagrams, package structure tables, detailed kernel-space packet filter stage descriptions (Phase 0-7) |

---

## 2. Core Process & Document Alignment Analysis

### 2.1 Dataplane & Control Plane Startup/Hot Reload Flow
* **In [project_architecture_diagrams.md](project_architecture_diagrams.md)**:
  * Part 1 uses **Mermaid flowcharts** to detail the startup lifecycle of the dataplane (`netxfwdp`) and control plane agent (`netxfwagent`), covering phases such as `BootstrapDaemon`, `LoadOrCreateManager`, `ReconcileInterfaces`, `StartCoreModules`, etc.
* **In `docs/` documents**:
  * Aligns with [10-01_architecture.md](10-appendix/10-01_architecture.md)'s **data path fine-grained package structure** design, detailing the responsibilities of sub-packages like `lifecycle/`, `backend/`, `maps/`, etc.
  * Aligns with [10-02_architecture_diagrams.md](10-appendix/10-02_architecture_diagrams.md)'s **Hot Reload Flow**, describing how userspace `ConfigCache` uses `Migrator` to perform iterative Map data copying and Link updates during capacity changes or incremental reloads, achieving seamless atomic replacement.

### 2.2 Network Interface Attach/Detach Flow
* **In [project_architecture_diagrams.md](project_architecture_diagrams.md)**:
  * Part 3, Section 2 uses **code-level function call chains** to connect the underlying implementation of network interface attachment ([lifecycle_xdp.go](../internal/datapath/xdp/backend/lifecycle_xdp.go)):
    1. **Atomic Hot Update**: Detects existing Link via `link.LoadPinnedLink`, calls `Update` to hot-replace bytecode.
    2. **Multi-mode Fallback Attachment**: Attempts `Offload` (hardware offload) -> `Native` (driver mode) -> `Generic` (generic mode) sequentially, then calls `Pin` for persistence.
    3. **TC (Traffic Control) Attachment**: Calls `link.AttachTCX` to attach `TcEgress` to the egress direction for outbound connection tracking.
* **In `docs/` documents**:
  * Corresponds to [10-01_architecture.md](10-appendix/10-01_architecture.md)'s **infrastructure layer** design and module division, as well as [10-02_architecture_diagrams.md](10-appendix/10-02_architecture_diagrams.md)'s static diagrams of TC attachment and `ct_map` connection tracking flow.

### 2.3 Security Policy Rule Sync Flow
* **In [project_architecture_diagrams.md](project_architecture_diagrams.md)**:
  * Part 3, Section 3 demonstrates the underlying function-level flow of the sync phase using `PortModule` as an example ([port.go](../internal/daemon/engine/port.go)):
    1. **Fetch**: Calls `m.rule.List` to pull existing rules from the active BPF Map.
    2. **Calculate diff & clean**: Compares with the desired configuration, calls `m.rule.RemoveIPPortRule` to remove redundant mappings.
    3. **Sync write**: Iterates through the latest policy set, calls `m.rule.AddIPPortRule` to write new rules to the kernel.
* **In `docs/` documents**:
  * This flow is the logical extension of [10-01_architecture.md](10-appendix/10-01_architecture.md)'s **service layer/application service layer/control plane** managing bidirectional data consistency between eBPF Maps and local configuration files.

---

## 3. Complementary Relationship with Kernel-Space Packet Filter Flow

* [10-03_packet_filter_flow.md](10-appendix/10-03_packet_filter_flow.md) details the **8 logical phases** (Phase 0-7) of the XDP hook (`xdp_firewall`) processing packets in the kernel, including Bogon filtering, whitelist passthrough, dynamic/static blacklist matching, IP rate limiting, connection tracking, IP+Port granular control, and default policy.
* [project_architecture_diagrams.md](project_architecture_diagrams.md) complements from a **userspace control flow** perspective, explaining:
  - How the global cache configurations required by the above filtering stages (e.g., `cached_default_deny`) are initialized in userspace and synchronously updated at sampling intervals (every 1000 packets).
  - How the BPF Maps (e.g., `lock_list`, `whitelist`, `ip_port_rules`) relied upon by core filtering stages are updated and hot-fixed in userspace through incremental mechanisms.

---

## 4. Complete Mapping & Index Reference Table

For quick navigation between "architecture diagrams", "process documentation", and "code implementation" during development and debugging, refer to the following table:

| Business/System Flow | docs/ Document Section | project_architecture_diagrams.md Location | Core Go Source / Implementation |
| :--- | :--- | :--- | :--- |
| **System Layered Architecture (DDD)** | [10-01_architecture.md:L125-198](10-appendix/10-01_architecture.md#L125-L198) | *N/A (focuses on dynamic flow)* | Entire `internal/` directory structure |
| **Dataplane Startup & eBPF Loading** | [10-01_architecture.md:L200-215](10-appendix/10-01_architecture.md#L200-L215) | Section 1.1 (Mermaid) & 3.1 (NewManager steps) | [xdp_manager.go](../internal/datapath/xdp/backend/xdp_manager.go) |
| **Network Interface Attachment (XDP/TC)** | [10-02_architecture_diagrams.md:L63-69](10-appendix/10-02_architecture_diagrams.md#L63-L69) | Section 1.1 Step 6 & 3.2 (Attach steps) | [lifecycle_xdp.go](../internal/datapath/xdp/backend/lifecycle_xdp.go) |
| **Rule Deployment & Map Sync** | [10-02_architecture_diagrams.md:L232-306](10-appendix/10-02_architecture_diagrams.md#L232-L306) | Section 2 (Port sync call graph) & 3.3 (Sync steps) | [port.go](../internal/daemon/engine/port.go) |
| **Packet Filter Core Logic** | [10-03_packet_filter_flow.md](10-appendix/10-03_packet_filter_flow.md) & [10-04_summary_packet_filter.md](10-appendix/10-04_summary_packet_filter.md) | *N/A (focuses on userspace interaction)* | [netxfw.bpf.c](../bpf/netxfw.bpf.c) (kernel filter entry) |

---

## 5. Summary & Recommendations

> [!TIP]
> **When should you read the system design architecture documentation (`docs/`)?**
> When you need to modify business logic, add new extension modules, or adjust basic configuration parameters, prioritize reading [10-01_architecture.md](10-appendix/10-01_architecture.md) to ensure your modifications comply with DDD (Domain-Driven Design) and hexagonal architecture layering.

> [!IMPORTANT]
> **When should you refer to the core process report ([project_architecture_diagrams.md](project_architecture_diagrams.md))?**
> When you need to optimize eBPF resource loading, fix network interface attachment anomalies, or debug the sync performance of incremental rule deployment, refer to the dynamic call chains provided by this report and navigate directly to the corresponding specific code lines for breakpoint debugging or code refactoring.