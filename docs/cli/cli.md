# 命令行手册 (CLI Manual)

`netxfw` 提供了一个简单的命令行界面，用于管理防火墙服务和操作 IP 规则列表。

## 通用标志

以下标志适用于大多数子命令：

| 标志 | 简写 | 说明 |
|---|---|---|
| `--config <path>` | `-c` | 指定配置文件路径（默认 `/etc/netxfw/config.yaml`） |
| `--interface <name>` | `-i` | 指定网络接口 |
| `--mode <dp\|agent>` | - | 运行模式（`dp` 数据面 / `agent` 控制面） |

---

## 命令概览

### 快捷命令

| 命令 | 参数 | 说明 |
|---|---|---|
| `block <ip>` | IP/CIDR | 快速封禁 IP（加入黑名单） |
| `unlock <ip>` | IP/CIDR | 快速解封 IP（从黑名单移除） |
| `allow <ip> [port]` | IP/CIDR [端口] | 快速加入白名单 |
| `unallow <ip>` | IP/CIDR | 快速从白名单移除 |
| `clear` | 无 | 清空黑名单 |

### system 系统管理

| 命令 | 参数 | 说明 |
|---|---|---|
| `system on [iface...]` | 接口名 | 加载 XDP 程序（`load` 别名） |
| `system off [iface...]` | 接口名 | 卸载 XDP 程序（`unload` 别名） |
| `system load` | `-i <iface>` | 加载 XDP 驱动到指定接口 |
| `system unload` | `-i <iface>` | 卸载 XDP 驱动 |
| `system reload` | `-i <iface>` | 热重载 XDP 程序（无损更新） |
| `system daemon` | `-c -i` | 启动后台守护进程 |
| `system status` | `-c -i` | 查看运行时状态和统计信息 |
| `system init` | `-c` | 初始化默认配置文件 |
| `system test` | `-c` | 测试配置文件有效性 |
| `system update` | 无 | 从 GitHub 检查并安装更新 |
| `system sync to-config` | `-c -i` | 将 BPF Map 状态同步到配置文件 |
| `system sync to-map` | `-c -i` | 将配置文件加载到 BPF Map |

### rule 规则管理

| 命令 | 参数 | 说明 |
|---|---|---|
| `rule add <ip> [port] <allow\|deny>` | IP, 端口, 动作 | 添加 IP 或 IP+端口规则 |
| `rule remove <ip>` | IP/CIDR | 移除规则 |
| `rule list` | 可选过滤参数 | 查看所有规则列表 |
| `rule import <type> <file>` | 类型, 文件 | 批量导入规则（TXT/JSON/YAML） |
| `rule export <file> [--format]` | 文件名, 格式 | 导出规则（JSON/YAML/CSV） |
| `rule clear` | 无 | 清空黑名单 |

### limit 限速管理

| 命令 | 参数 | 说明 |
|---|---|---|
| `limit add <ip> <rate> <burst>` | IP, 速率, 突发 | 为指定 IP 设置 PPS 限速 |
| `limit remove <ip>` | IP | 移除限速规则 |
| `limit list` | 无 | 查看所有限速规则 |

### security 安全策略

| 命令 | 参数 | 说明 |
|---|---|---|
| `security fragments <true\|false>` | 布尔值 | 启用/禁用分片包丢弃 |
| `security strict-tcp <true\|false>` | 布尔值 | 启用/禁用严格 TCP 标志验证 |
| `security syn-limit <true\|false>` | 布尔值 | 启用/禁用 SYN Flood 保护 |
| `security bogon <true\|false>` | 布尔值 | 启用/禁用 Bogon 过滤 |
| `security auto-block <true\|false>` | 布尔值 | 启用/禁用自动封锁 |
| `security auto-block-expiry <seconds>` | 秒数 | 设置自动封锁过期时间 |

### port 端口管理

| 命令 | 参数 | 说明 |
|---|---|---|
| `port add <port>` | 端口号 | 将端口加入全局允许列表 |
| `port remove <port>` | 端口号 | 从允许列表移除端口 |

### perf 性能监控

| 命令 | 参数 | 说明 |
|---|---|---|
| `perf show` | `-c -i` | 显示所有性能统计 |
| `perf latency` | `-c -i` | 显示 Map 操作延迟统计 |
| `perf cache` | `-c -i` | 显示缓存命中率统计 |
| `perf traffic` | `-c -i` | 显示实时流量统计（PPS/BPS/丢包率） |
| `perf reset` | `-c -i` | 重置性能统计计数器 |

### 其他

| 命令 | 参数 | 说明 |
|---|---|---|
| `conntrack` | 无 | 查看内核活跃连接追踪表 |
| `version` | `[--short]` | 查看版本及 SDK 状态 |
| `web` | 无 | 显示 Web 控制台信息 |

---

## 详细说明

### 1. XDP 程序管理

`netxfw` 提供多种方式管理 XDP 程序的加载和卸载：

| 功能 | 命令 |
|---|---|
| 加载 XDP | `netxfw system on eth0` 或 `netxfw system load -i eth0` |
| 卸载 XDP | `netxfw system off eth0` 或 `netxfw system unload -i eth0` |
| 卸载全部 | `netxfw system off` |
| 热重载 | `netxfw system reload -i eth0` |

```bash
# 加载到指定网卡
sudo netxfw system on eth0

# 加载到多个网卡
sudo netxfw system on eth0 eth1 eth2

# 使用配置文件中的默认网卡
sudo netxfw system on

# 卸载所有网卡上的 XDP
sudo netxfw system off

# 热重载（无损更新，不中断现有连接）
sudo netxfw system reload -i eth0
```

### 2. 系统状态 (system status)

显示防火墙运行状态、统计信息和资源利用率。

```bash
# 查看系统状态
sudo netxfw system status

# 指定配置文件
sudo netxfw system status -c /etc/netxfw/config.yaml

# 查看特定接口的统计
sudo netxfw system status -i eth0
```

**输出内容包含**：流量速率、通过/丢弃统计、连接追踪健康度、BPF Map 使用率、协议分布、安全策略概览、接口状态。

### 3. 快捷封禁与解封

针对紧急情况的快捷命令，无需 SDK 子命令：

```bash
# 立即封禁 IP
sudo netxfw block 1.2.3.4

# 封禁 CIDR 网段
sudo netxfw block 192.168.100.0/24

# 立即解封
sudo netxfw unlock 1.2.3.4

# 加入白名单
sudo netxfw allow 1.2.3.4

# 指定白名单端口
sudo netxfw allow 1.2.3.4 443

# 从白名单移除
sudo netxfw unallow 1.2.3.4

# 清空黑名单
sudo netxfw clear
```

### 4. 规则管理 (rule)

支持细粒度的访问控制。

```bash
# 将 IP 加入白名单（允许所有流量）
sudo netxfw rule add 1.2.3.4 allow

# 将 IP 加入黑名单（封禁所有流量）
sudo netxfw rule add 5.6.7.8 deny

# 封禁特定 IP 访问特定端口
sudo netxfw rule add 5.6.7.8 80 deny

# 查看所有规则
sudo netxfw rule list

# 移除规则
sudo netxfw rule remove 1.2.3.4
```

### 5. 批量导入 (rule import)

支持从文本或结构化文件批量导入规则。

```bash
# 导入黑名单（每行一个 IP/CIDR）
sudo netxfw rule import deny blacklist.txt

# 导入白名单
sudo netxfw rule import allow whitelist.txt

# 从 JSON/YAML 文件导入所有规则
sudo netxfw rule import all rules.json
sudo netxfw rule import all rules.yaml
```

**文本格式**：每行一个 IP 或 CIDR，支持 `#` 注释。

**JSON 格式**：
```json
{
  "blacklist": [{"type": "blacklist", "ip": "10.0.0.1"}],
  "whitelist": [{"type": "whitelist", "ip": "127.0.0.1/32"}],
  "ipport_rules": [{"type": "ipport", "ip": "192.168.1.1", "port": 80, "action": "allow"}]
}
```

### 6. 规则导出 (rule export)

```bash
# 导出为 JSON（默认）
sudo netxfw rule export rules.json

# 导出为 YAML
sudo netxfw rule export rules.yaml --format yaml

# 导出为 CSV
sudo netxfw rule export rules.csv --format csv
```

### 7. 限速管理 (limit)

在 XDP 层对指定 IP 或网段进行 PPS（每秒包数）限速，支持 IPv4/IPv6/CIDR。

```bash
# 限制 1000 pps，最大突发 2000
sudo netxfw limit add 1.2.3.4 1000 2000

# 限制 IPv6 地址
sudo netxfw limit add 2001:db8::1 500 1000

# 限制整个网段
sudo netxfw limit add 192.168.1.0/24 5000 10000

# 查看限速规则
sudo netxfw limit list

# 移除限速规则
sudo netxfw limit remove 1.2.3.4
```

### 8. 安全策略 (security)

动态调整防火墙的安全行为，立即生效，无需重载。

```bash
# 禁用分片包丢弃
sudo netxfw security fragments false

# 启用严格 TCP 标志验证
sudo netxfw security strict-tcp true

# 启用 SYN Flood 保护
sudo netxfw security syn-limit true

# 启用 Bogon 过滤
sudo netxfw security bogon true

# 启用自动封锁
sudo netxfw security auto-block true

# 设置自动封锁过期时间（600 秒）
sudo netxfw security auto-block-expiry 600
```

### 9. 端口管理 (port)

管理全局允许端口列表。

```bash
# 允许特定端口
sudo netxfw port add 8080

# 移除允许端口
sudo netxfw port remove 8080
```

### 10. 配置同步 (system sync)

在 BPF Map（运行时）与配置文件（磁盘）之间双向同步。

```bash
# 将运行时状态持久化到配置文件
sudo netxfw system sync to-config

# 将配置文件重新加载到运行时
sudo netxfw system sync to-map
```

### 11. 性能监控 (perf)

```bash
sudo netxfw perf show       # 显示所有性能统计
sudo netxfw perf latency    # Map 操作延迟
sudo netxfw perf cache      # 缓存命中率
sudo netxfw perf traffic    # 实时流量 PPS/BPS
sudo netxfw perf reset      # 重置统计计数器
```

### 12. 守护进程模式 (system daemon)

```bash
# 使用配置文件中指定的接口启动
sudo netxfw system daemon

# 指定接口启动
sudo netxfw system daemon -i eth0

# 指定配置文件和接口
sudo netxfw system daemon -c /etc/netxfw/config.yaml -i eth0
```

> **PID 文件说明**：
> - 指定接口时：`/var/run/netxfw_<interface>.pid`（支持多实例并行）
> - 未指定接口时：`/var/run/netxfw.pid`

### 13. 版本信息 (version)

```bash
netxfw version           # 详细版本及 SDK 状态
netxfw version --short   # 仅输出版本号（适用于脚本）
```

### 14. 配置初始化与验证

```bash
# 初始化默认配置文件
sudo netxfw system init

# 测试配置文件是否有效
sudo netxfw system test

# 手动检查并安装更新
sudo netxfw system update
```
