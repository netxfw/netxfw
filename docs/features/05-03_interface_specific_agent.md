# 通用接口和配置参数支持 (Universal Interface and Config Parameter Support)

## 概述

netxfw 支持为多个命令提供通用的接口 (`-i`) 和配置文件 (`-c`) 参数，实现灵活的多网卡管理和配置管理。这种设计允许多个命令针对特定网络接口运行，并支持指定配置文件。

## 功能特性

### 1. 通用接口参数支持
- 多个命令支持 `-i` 或 `--interface` 参数指定网络接口
- 支持指定单个或多个网络接口
- 支持通过位置参数指定接口
- 当未指定接口时，使用配置文件中的默认接口

### 2. 通用配置文件参数支持
- 多个命令支持 `-c` 或 `--config` 参数指定配置文件
- 命令行指定的配置文件优先级高于默认配置文件
- 支持接口参数与配置文件参数组合使用

### 3. 接口特定的 PID 文件管理
- 当使用特定接口运行时，会为每个接口创建独立的 PID 文件：`/var/run/netxfw_<interface>.pid`
- 当未指定接口时，使用默认 PID 文件：`/var/run/netxfw.pid`
- 支持在同一系统上运行多个独立的实例

### 4. 配置文件灵活性
- 支持在配置文件中通过 `base.interfaces` 字段指定默认接口
- 支持通过命令行参数覆盖配置文件中的接口设置
- 命令行参数优先级高于配置文件设置

## 支持的命令

以下命令支持 `-c` 配置文件参数：

### System Commands
- `netxfw system init -c <config_file>`
- `netxfw system status -c <config_file>`
- `netxfw system test -c <config_file>`
- `netxfw system daemon -c <config_file>`
- `netxfw system load -c <config_file> -i <interface>`
- `netxfw system unload -c <config_file> -i <interface>`
- `netxfw system reload -c <config_file> -i <interface>`

### Performance Commands
- `netxfw perf show -c <config_file>`
- `netxfw perf latency -c <config_file>`
- `netxfw perf cache -c <config_file>`
- `netxfw perf traffic -c <config_file>`
- `netxfw perf reset -c <config_file>`

### Rule Commands
- `netxfw rule add <ip> -c <config_file>`
- `netxfw rule remove <ip> -c <config_file>`
- `netxfw rule list -c <config_file>`
- `netxfw rule import <type> <file> -c <config_file>`
- `netxfw rule export <file> -c <config_file>`
- `netxfw rule clear -c <config_file>`

### Limit Commands
- `netxfw limit add <ip> <rate> <burst> -c <config_file>`
- `netxfw limit remove <ip> -c <config_file>`
- `netxfw limit list -c <config_file>`

## 使用方法

### 命令行使用

```bash
# 使用配置文件中指定的接口启动 Agent
sudo netxfw system agent

# 指定特定接口启动 Agent
sudo netxfw system agent -i eth0

# 指定多个接口启动 Agent
sudo netxfw system agent -i eth0,eth1

# 使用命令行参数覆盖配置文件中的接口设置
sudo netxfw system agent -i eth2 eth3

# 使用指定配置文件启动 Agent
sudo netxfw system agent -c /path/to/config.yaml

# 使用指定配置文件和特定接口启动 Agent
sudo netxfw system agent -c /path/to/config.yaml -i eth0

# 使用配置文件中指定的接口启动守护进程
sudo netxfw system daemon

# 指定特定接口启动守护进程
sudo netxfw system daemon -i eth0

# 指定多个接口启动守护进程
sudo netxfw system daemon -i eth0,eth1

# 使用指定配置文件启动守护进程
sudo netxfw system daemon -c /path/to/config.yaml

# 使用指定配置文件和特定接口启动守护进程
sudo netxfw system daemon -c /path/to/config.yaml -i eth0

# 查看系统状态
sudo netxfw system status

# 查看特定接口的状态
sudo netxfw system status -i eth0

# 使用指定配置文件查看状态
sudo netxfw system status -c /path/to/config.yaml

# 使用指定配置文件查看特定接口的状态
sudo netxfw system status -c /path/to/config.yaml -i eth0,eth1

# 查看性能统计
sudo netxfw perf show
sudo netxfw perf show -c /path/to/config.yaml

# 查看规则列表
sudo netxfw rule list
sudo netxfw rule list -c /path/to/config.yaml

# 添加限速规则
sudo netxfw limit add 192.168.1.100 1000 2000
sudo netxfw limit add 192.168.1.100 1000 2000 -c /path/to/config.yaml
```

### 配置文件设置

在 `/etc/netxfw/config.yaml` 中：

```yaml
base:
  # 指定默认的网络接口
  interfaces: ["eth0", "eth1"]
  # 其他配置...
```

## PID 文件管理

### 文件命名规则
- 接口特定：`/var/run/netxfw_<interface>.pid` (例如 `/var/run/netxfw_eth0.pid`)
- 默认：`/var/run/netxfw.pid`

### 生命周期管理
- 启动时：根据接口列表创建相应的 PID 文件
- 关闭时：清理所有相关的 PID 文件
- 异常终止：下次启动时自动清理过期的 PID 文件

## 系统状态检查

### 基本状态检查
```bash
# 检查系统状态
sudo netxfw system status
```

### 指定配置文件的状态检查
```bash
# 使用指定配置文件检查状态
sudo netxfw system status -c /path/to/custom/config.yaml
```

## 最佳实践

### 1. 生产环境部署
- 在配置文件中预设常用接口
- 使用命令行参数进行临时调试
- 监控多个 PID 文件以确保所有接口的 Agent 实例正常运行

### 2. 运维注意事项
- 确保有足够的权限管理 `/var/run/` 目录下的 PID 文件
- 定期检查 PID 文件的完整性
- 在容器环境中注意 PID 文件的持久化问题

## 故障排除

### PID 文件冲突
- 检查是否存在残留的 PID 文件
- 验证对应的进程是否仍在运行
- 手动清理过期的 PID 文件后重启服务

### 接口不可用
- 确认指定的网络接口存在且处于活动状态
- 检查接口名称拼写是否正确
- 验证是否有足够的权限访问网络接口