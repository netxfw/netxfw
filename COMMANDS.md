# netxfw 命令参考手册 (重构版)

> **注意**：本文档基于重构后的最新 CLI 架构。部分旧命令（如 `block`）已被 `deny` 取代。

## 🚀 核心管理命令

| 命令 | 说明 | 别名 |
|------|------|------|
| `netxfw status` | 查看防火墙运行状态 | - |
| `netxfw enable` | 启动防火墙并加载 XDP 程序 | `start` (隐藏) |
| `netxfw disable` | 停止防火墙并卸载 XDP 程序 | `stop` (隐藏) |
| `netxfw reload` | 热重载配置（仅同步 BPF Map，不重启） | - |
| `netxfw reset` | 重置防火墙（清空所有规则并恢复初始状态） | - |
| `netxfw version` | 查看版本信息 | - |

## 🛡️ 规则快速操作

| 命令 | 说明 | 别名 |
|------|------|------|
| `netxfw allow <ip>[:port]` | 允许指定 IP 或 IP:端口（加入白名单） | - |
| `netxfw deny <ip>[:port]` | 拒绝指定 IP 或 IP:端口（加入黑名单） | - |
| `netxfw del <ip>[:port]` | 移除指定 IP 或端口的规则 | `delete`, `remove` |
| `netxfw list` | 查看当前生效的封禁列表 | - |
| `netxfw clear` | 清空黑名单（支持 `--dynamic` 仅清空临时封禁） | - |

## ⚙️ 系统级命令 (`netxfw system`)

用于底层驱动管理和系统集成：

| 子命令 | 说明 |
|--------|------|
| `netxfw system load` | 加载 XDP 驱动程序 |
| `netxfw system unload` | 卸载 XDP 驱动程序 |
| `netxfw system status` | 查看底层驱动和 Map 详细状态 |
| `netxfw system reload` | 强制重新加载驱动和配置 |
| `netxfw system sync` | 同步配置文件到 BPF Map |

## 📂 规则导入导出 (`netxfw rule`)

| 子命令 | 说明 |
|--------|------|
| `netxfw rule add <ip> <action>` | 添加规则（action: allow/deny） |
| `netxfw rule del <ip>` | 删除规则 |
| `netxfw rule list` | 列出所有结构化规则 |
| `netxfw rule import <type> <file>` | 从文件导入规则 (`type`: lock/allow/rules/all/binary) |
| `netxfw rule export <file>` | 导出规则（支持 JSON/TOML/CSV/Binary） |

---

## 📖 使用示例

### 1. 快速封禁与解封
```bash
# 永久封禁
sudo netxfw deny 1.2.3.4

# 临时封禁 1 小时 (使用 --ttl 参数)
sudo netxfw deny 1.2.3.4 --ttl 1h

# 解封 IP
sudo netxfw del 1.2.3.4
```

### 2. 精确端口控制
```bash
# 仅允许 192.168.1.100 访问 8080 端口
sudo netxfw allow 192.168.1.100:8080

# 拒绝所有对 443 端口的访问（通过全局端口管理）
sudo netxfw port del 443
```

### 3. 查看状态
```bash
# 查看基础状态
netxfw status

# 查看详细统计信息
netxfw status -v
```

### 4. 批量操作
```bash
# 导出当前所有规则到 JSON
netxfw rule export backup.json

# 从二进制压缩包快速导入大规模黑名单
netxfw rule import binary high_risk_ips.bin.zst
```

## 💡 参数说明
- `--ttl, -t`: 用于 `deny` 命令，设置临时封禁时长（如 `30s`, `15m`, `2h`, `1d`）。
- `--config, -c`: 指定配置文件路径。
- `--mode`: 运行模式（`dp` 为数据平面，`agent` 为控制平面）。
