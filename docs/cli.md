# 命令行手册 (CLI Manual)

`netxfw` 提供了一个简单的命令行界面，用于管理防火墙服务和操作 IP 锁定列表。

## 命令概览

| 命令 | 参数 | 描述 |
| :--- | :--- | :--- |
| `daemon` | 无 | 启动守护进程，负责指标收集、规则清理和 API 服务 |
| `load xdp` | 无 | 加载 BPF 程序并挂载到所有物理网卡 |
| `unload xdp` | 无 | 卸载 BPF 程序并清理固定 Map |
| `reload xdp` | 无 | 热重载配置并无损更新 BPF 程序 |
| `conntrack` | 无 | 查看当前内核中的活跃连接追踪表 |
| `rule add` | `<IP> [port] <allow/deny>` | 添加 IP 或 IP+端口 规则 |
| `rule list` | `rules / conntrack` | 查看规则列表或连接列表 |
| `lock` | `<IP>` | 快捷命令：全局封禁指定 IP |
| `allow` | `<IP> [port]` | 快捷命令：将 IP 加入白名单 |
| `web` | `start / stop` | 管理 Web 控制台服务 |
| `ai-mcp` | 无 | 启动 AI MCP 服务 (stdio 模式) |

---

## 详细说明

### 1. 守护进程 (daemon)
`netxfw` 的核心运行模式。在 `daemon` 模式下，程序会：
- 监控内核 BPF Map 状态。
- 自动清理过期的动态规则。
- 暴露 Prometheus 指标 (默认 :9100)。
- 启动 Web API 供 CLI 和 Web UI 调用。

```bash
sudo netxfw daemon
```

### 2. 规则管理 (rule)
支持细粒度的访问控制。
- **添加规则**：
  ```bash
  # 允许来自 1.2.3.4 的所有流量
  sudo netxfw rule add 1.2.3.4 allow
  # 拦截来自 5.6.7.8 访问 80 端口的流量
  sudo netxfw rule add 5.6.7.8 80 deny
  ```
- **查看规则**：
  ```bash
  sudo netxfw rule list rules
  ```

### 3. 连接追踪 (conntrack)
实时查看内核中的有状态连接。这对于排查网络连通性问题非常有用。

```bash
sudo netxfw conntrack
```
**输出示例：**
```text
Source          Port  Destination     Port  Protocol
--------------------------------------------------------------------------------
192.168.1.100   54321 1.1.1.1         443   TCP
```

### 4. 快速封禁与解封 (lock/unlock)
针对紧急情况的快捷命令。

```bash
# 立即封禁
sudo netxfw lock 1.2.3.4
# 立即解封
sudo netxfw unlock 1.2.3.4
```

### 5. 热重载 (reload)
当您修改了 `/etc/netxfw/config.yaml`（例如调整了 Map 容量或默认策略）后，可以使用此命令实现无损重载。

```bash
sudo netxfw reload xdp
```
该命令会自动将旧 Map 中的数据迁移到新 Map，确保现有连接不中断。

### 6. AI MCP 服务 (ai-mcp)
`ai-mcp` 是一个独立的二进制文件，用于支持 Model Context Protocol。它通常由 AI 客户端（如 Claude Desktop）启动。

```bash
# 手动测试（会进入 stdio 交互模式）
./ai-mcp
```
