# 命令行手册 (CLI Manual)

`netxfw` 提供了一个简单的命令行界面，用于管理防火墙服务和操作 IP 锁定列表。

## 命令概览

| 命令 | 参数 | 描述 |
| :--- | :--- | :--- |
| `daemon` | 无 | 启动守护进程，负责指标收集、规则清理和 API 服务 |
| `system on` | `[interface...]` | 加载 XDP 程序 (load 的别名) |
| `system off` | `[interface...]` | 卸载 XDP 程序 (unload 的别名) |
| `system load` | `[-i interface]` | 加载 BPF 程序并挂载到指定网卡 |
| `system unload` | `[-i interface]` | 卸载 BPF 程序并清理固定 Map |
| `system reload` | `[-i interface]` | 热重载配置并无损更新 BPF 程序 |
| `plugin load` | `<path> <index>` | 动态加载 BPF 插件到指定索引 (2-15) |
| `plugin remove`| `<index>` | 移除指定索引位的 BPF 插件 |
| `conntrack` | 无 | 查看当前内核中的活跃连接追踪表 |
| `rule add` | `<IP> [port] <allow/deny>` | 添加 IP 或 IP+端口 规则 |
| `rule list` | `rules / conntrack` | 查看规则列表或连接列表 |
| `rule import` | `[type] <file>` | 导入规则（支持文本/JSON/YAML） |
| `rule export` | `<file> [--format]` | 导出规则到文件（支持 JSON/YAML/CSV） |
| `limit add` | `<IP> <rate> <burst>` | 为指定 IP 设置 PPS 限速 |
| `limit remove`| `<IP>` | 移除限速规则 |
| `limit list` | 无 | 查看所有限速规则 |
| `lock` | `<IP>` | 快捷命令：全局封禁指定 IP |
| `allow` | `<IP> [port]` | 快捷命令：将 IP 加入白名单 |
| `system sync` | `to-config / to-map` | 同步内存规则到配置文件，或从配置文件加载到内存 |
| `system status`| 无 | 查看系统状态和统计信息 |
| `perf show` | 无 | 显示所有性能统计信息 |
| `perf latency` | 无 | 显示 Map 操作延迟统计 |
| `perf cache` | 无 | 显示缓存命中率统计 |
| `perf traffic` | 无 | 显示实时流量统计 |
| `perf reset` | 无 | 重置性能统计计数器 |
| `web` | `start / stop` | 管理 Web 控制台服务 |

---

## 详细说明

### 1. XDP 程序管理 (system on/off/load/unload)

`netxfw` 提供多种方式管理 XDP 程序的加载和卸载：

#### 命令对照表

| 功能 | 命令格式 1 | 命令格式 2 | 命令格式 3 |
|------|-----------|-----------|-----------|
| **加载 XDP** | `netxfw system load -i eth0` | `netxfw system on -i eth0` | `netxfw system on eth0` |
| **卸载 XDP** | `netxfw system unload -i eth0` | `netxfw system off -i eth0` | `netxfw system off eth0` |
| **卸载全部** | `netxfw system unload` | `netxfw system off` | - |

#### 使用示例

```bash
# 加载 XDP 到指定网卡
sudo netxfw system on eth0

# 加载到多个网卡
sudo netxfw system on eth0 eth1 eth2

# 使用配置文件中的默认网卡
sudo netxfw system on

# 卸载指定网卡上的 XDP
sudo netxfw system off eth0

# 卸载所有网卡上的 XDP
sudo netxfw system off

# 使用 -i 标志指定网卡
sudo netxfw system load -i eth0
sudo netxfw system unload -i eth0
```

### 2. 守护进程 (daemon)
`netxfw` 的核心运行模式。在 `daemon` 模式下，程序会：
- 监控内核 BPF Map 状态。
- 自动清理过期的动态规则。
- 暴露 Prometheus 指标 (默认 :9100)。
- 启动 Web API 供 CLI 和 Web UI 调用。

```bash
sudo netxfw daemon
```

### 3. 规则管理 (rule)
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

### 4. 连接追踪 (conntrack)
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

### 5. 快速封禁与解封 (lock/unlock)
针对紧急情况的快捷命令。

```bash
# 立即封禁
sudo netxfw lock 1.2.3.4
# 立即解封
sudo netxfw unlock 1.2.3.4
```

### 6. 流量控制 (limit)
在 XDP 层面对指定 IP 或网段进行 PPS（每秒数据包数）限速。支持 IPv4 和 IPv6。

- **开启全局限速功能**：
  ```bash
  sudo netxfw system ratelimit true
  ```
- **添加限速规则**：
  ```bash
  # 限制 1.2.3.4 的流量为每秒 100 个包，最大突发 200 个包
  sudo netxfw limit add 1.2.3.4 100 200

  # 限制 IPv6 地址 ::1 的流量为每秒 500 个包
  sudo netxfw limit add ::1 500 1000

  # 限制整个网段 192.168.1.0/24
  sudo netxfw limit add 192.168.1.0/24 1000 2000
  ```
- **查看限速状态**：
  ```bash
  sudo netxfw limit list
  ```
- **移除限速规则**：
  ```bash
  sudo netxfw limit remove 1.2.3.4
  ```

### 7. 热重载 (reload)
当您修改了 `/etc/netxfw/config.yaml`（例如调整了 Map 容量或默认策略）后，可以使用此命令实现无损重载。

```bash
sudo netxfw reload xdp
```
该命令会自动将旧 Map 中的数据迁移到新 Map，确保现有连接不中断。

### 8. 配置同步 (sync)
支持内存状态（BPF Maps）与配置文件（config.yaml）之间的双向同步，确保运维一致性。

- **同步到配置文件**（Memory -> Disk）：
  将当前 BPF Map 中的动态规则（黑名单、限速规则等）写入 `config.yaml`，实现持久化。
  ```bash
  sudo netxfw system sync to-config
  ```

- **同步到内存**（Disk -> Memory）：
  将 `config.yaml` 中的规则重新加载到 BPF Map 中（类似于热重载，但不重启 BPF 程序）。
  ```bash
  sudo netxfw system sync to-map
  ```

### 9. 批量导入 (import)
支持从文本文件或结构化文件（JSON/YAML）批量导入规则。

#### 文本格式导入
```bash
# 导入黑名单（每行一个 IP 或网段）
sudo netxfw rule import deny blacklist.txt

# 导入白名单（每行一个 IP 或网段）
sudo netxfw rule import allow whitelist.txt

# 导入 IP+端口规则（每行格式：IP:Port:Action）
sudo netxfw rule import rules ipport.txt
```
**文本文件格式示例**：
```text
# 每行一个 IP 或网段
1.2.3.4
192.168.0.0/24
2001:db8::1
```

#### JSON/YAML 格式导入
支持导入 `rule export` 导出的结构化文件，实现规则备份与恢复的完整闭环。

```bash
# 从 JSON 文件导入所有规则
sudo netxfw rule import all rules.json

# 从 YAML 文件导入所有规则
sudo netxfw rule import all rules.yaml
```
**JSON 文件格式示例**：
```json
{
  "blacklist": [
    {"type": "blacklist", "ip": "10.0.0.1"},
    {"type": "blacklist", "ip": "192.168.0.0/24"}
  ],
  "whitelist": [
    {"type": "whitelist", "ip": "127.0.0.1/32"}
  ],
  "ipport_rules": [
    {"type": "ipport", "ip": "192.168.1.1", "port": 80, "action": "allow"},
    {"type": "ipport", "ip": "10.0.0.2", "port": 443, "action": "deny"}
  ]
}
```

### 10. 规则导出 (export)
支持将当前所有防火墙规则导出为 JSON、YAML 或 CSV 格式的文件。

```bash
# 导出为 JSON 格式（默认）
sudo netxfw rule export rules.json

# 导出为 YAML 格式
sudo netxfw rule export rules.yaml --format yaml

# 导出为 CSV 格式
sudo netxfw rule export rules.csv --format csv
```
**导出内容包含**：
- 黑名单列表
- 白名单列表
- IP+端口规则

### 11. 性能监控 (perf)
提供实时性能监控功能，包括 Map 操作延迟、缓存命中率和流量统计。

```bash
# 显示所有性能统计信息
sudo netxfw perf show

# 显示 Map 操作延迟统计
sudo netxfw perf latency

# 显示缓存命中率统计
sudo netxfw perf cache

# 显示实时流量统计
sudo netxfw perf traffic

# 重置性能统计计数器
sudo netxfw perf reset
```
**性能统计包含**：
- **Map 操作延迟**：记录各类 BPF Map 操作的延迟统计（读/写/删除/迭代）
- **缓存命中率**：统计全局统计、丢弃详情、通过详情、Map 计数等缓存命中情况
- **实时流量**：显示当前/峰值/平均 PPS、BPS、丢弃率等流量指标

### 12. 插件管理 (plugin)
允许在不停止防火墙的情况下，动态扩展数据包处理逻辑。
- **加载插件**：
  ```bash
  # 将编译好的插件加载到索引 2
  sudo netxfw plugin load ./my_plugin.o 2
  ```
- **卸载插件**：
  ```bash
  sudo netxfw plugin remove 2
  ```
详情请参考 [插件开发指南](plugins.md)。
