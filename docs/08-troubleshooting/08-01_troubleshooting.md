# 故障排查指南 (Troubleshooting Guide)

本文档提供 netxfw 常见问题的诊断和解决方案。

## 目录

1. [常见错误及解决方案](#常见错误及解决方案)
2. [日志分析](#日志分析)
3. [性能问题诊断](#性能问题诊断)
4. [BPF Map 问题](#bpf-map-问题)
5. [网络连接问题](#网络连接问题)
6. [守护进程问题](#守护进程问题)

---

## 常见错误及解决方案

### 1. 权限不足错误

**错误信息**:
```
Error: permission denied
Error: failed to pin BPF map: operation not permitted
```

**原因**: XDP 程序需要 root 权限或 `CAP_BPF`、`CAP_NET_ADMIN` 能力。

**解决方案**:
```bash
# 使用 sudo 运行
sudo netxfw start

# 或者授予必要的能力
sudo setcap cap_bpf,cap_net_admin,cap_sys_admin+ep /usr/bin/netxfw
```

### 2. BPF 程序加载失败

**错误信息**:
```
Error: failed to load BPF program: invalid argument
Error: BPF program load failed
```

**可能原因及解决方案**:

| 原因 | 解决方案 |
|------|----------|
| 内核版本过低 | 升级到 Linux 5.10+ |
| BTF 不支持 | 启用 `CONFIG_DEBUG_INFO_BTF` |
| 内存不足 | 检查并释放内存 |
| Map 大小超限 | 减小 Map 容量配置 |

**检查内核支持**:
```bash
# 检查内核版本
uname -r

# 检查 BTF 支持
ls /sys/kernel/btf/vmlinux

# 检查 XDP 支持
bpftool feature | grep xdp
```

### 3. 网卡绑定失败

**错误信息**:
```
Error: failed to attach XDP program: no such device
Error: interface eth0 not found
```

**解决方案**:
```bash
# 列出可用网卡
ip link show

# 检查网卡状态
ip link show eth0

# 确保网卡 UP
sudo ip link set eth0 up
```

### 4. Map 操作失败

**错误信息**:
```
Error: map not found
Error: key does not exist
Error: map update failed
```

**诊断步骤**:
```bash
# 列出所有 BPF Map
sudo bpftool map list

# 查看 Map 详情
sudo bpftool map show name whitelist

# 查看 Map 内容
sudo bpftool map dump name whitelist
```

### 5. 配置文件错误

**错误信息**:
```
Error: invalid configuration
Error: yaml: unmarshal errors
```

**解决方案**:
```bash
# 验证配置文件语法
python3 -c "import yaml; yaml.safe_load(open('/etc/netxfw/config.yaml'))"

# 或使用 netxfw 验证
sudo netxfw validate --config /etc/netxfw/config.yaml
```

---

## 日志分析

### 日志位置

| 日志类型 | 位置 |
|----------|------|
| 守护进程日志 | `/var/log/netxfw/daemon.log` |
| 审计日志 | `/var/log/netxfw/audit.log` |
| 错误日志 | `/var/log/netxfw/error.log` |

### 日志级别

```yaml
# 配置文件中设置日志级别
log:
  level: info  # debug, info, warn, error
  output: /var/log/netxfw/daemon.log
```

### 常用日志分析命令

```bash
# 查看最近的错误
sudo tail -100 /var/log/netxfw/error.log

# 实时监控日志
sudo tail -f /var/log/netxfw/daemon.log

# 搜索特定错误
sudo grep -i "error\|failed" /var/log/netxfw/*.log

# 统计错误类型
sudo grep -c "error" /var/log/netxfw/daemon.log
```

### 日志级别说明

| 级别 | 说明 | 使用场景 |
|------|------|----------|
| DEBUG | 详细调试信息 | 开发调试 |
| INFO | 常规操作信息 | 生产环境 |
| WARN | 警告信息 | 需要关注 |
| ERROR | 错误信息 | 需要处理 |

---

## 性能问题诊断

### CPU 使用率过高

**诊断步骤**:
```bash
# 查看 CPU 使用率
top -p $(pgrep netxfw)

# 使用 perf 分析
sudo perf top -p $(pgrep netxfw)

# 查看 CPU 火焰图
sudo perf record -g -p $(pgrep netxfw) -- sleep 30
sudo perf script | stackcollapse-perf.pl | flamegraph.pl > cpu.svg
```

**常见原因及解决方案**:

| 原因 | 解决方案 |
|------|----------|
| 流量过大 | 启用硬件卸载 |
| Map 操作频繁 | 使用 per-CPU Map |
| 规则数量过多 | 优化规则，使用 CIDR 合并 |
| 连接跟踪过多 | 增大 conntrack Map 或缩短超时 |

### 内存使用过高

**诊断步骤**:
```bash
# 查看内存使用
ps aux | grep netxfw

# 查看 BPF Map 内存
sudo bpftool map show | grep -E "name|bytes"

# 查看详细内存映射
pmap -x $(pgrep netxfw)
```

**内存优化建议**:
```yaml
# 调整 Map 大小
capacity:
  lock_list: 100000      # 静态黑名单
  dyn_lock_list: 50000   # 动态黑名单
  conntrack: 50000       # 连接跟踪

# 缩短超时时间
conntrack:
  timeout: 300           # 连接超时（秒）
```

### 包处理延迟高

**诊断步骤**:
```bash
# 查看 XDP 处理统计
sudo netxfw status -v

# 查看丢包统计
sudo bpftool map dump name stats_global_map

# 使用 XDP 统计工具
sudo xdp-stat -d eth0
```

---

## BPF Map 问题

### Map 满了

**错误信息**:
```
Error: map is full
Error: failed to update map: no space left
```

**解决方案**:
```bash
# 查看当前 Map 使用情况
sudo netxfw status -v

# 清理动态黑名单
sudo netxfw dynamic clear

# 调整 Map 大小
# 编辑 /etc/netxfw/config.yaml
capacity:
  dyn_lock_list: 200000
```

### Map 数据不一致

**诊断步骤**:
```bash
# 导出 Map 数据
sudo bpftool map dump name whitelist > whitelist_backup.txt

# 验证数据一致性
sudo netxfw rule list --verify

# 重建 Map（谨慎操作）
sudo netxfw stop
sudo rm -rf /sys/fs/bpf/netxfw/*
sudo netxfw start
```

### Map 持久化问题

**问题**: 重启后规则丢失

**解决方案**:
```yaml
# 确保配置了持久化文件
persistence:
  enabled: true
  lock_list_file: /etc/netxfw/lock_list.txt
  whitelist_file: /etc/netxfw/whitelist.txt
```

```bash
# 手动保存规则
sudo netxfw rule export /etc/netxfw/rules.yaml

# 启动时自动加载
sudo netxfw start --load-rules /etc/netxfw/rules.yaml
```

---

## 网络连接问题

### 无法连接到服务器

**诊断步骤**:
```bash
# 检查是否被拦截
sudo netxfw deny list
sudo netxfw allow list

# 查看连接跟踪
sudo netxfw conntrack list | grep <IP>

# 检查端口规则
sudo netxfw rule list

# 查看实时丢包
sudo netxfw status -v | grep "drop"
```

**常见原因**:

| 原因 | 检查命令 | 解决方案 |
|------|----------|----------|
| IP 被封禁 | `netxfw deny list` | `netxfw deny del <IP>` |
| 默认拒绝策略 | `netxfw status` | 添加白名单或允许规则 |
| 端口被阻止 | `netxfw rule list` | `netxfw allow port <PORT>` |
| 速率限制 | `netxfw limit list` | 调整或移除限制 |

### SSH 连接被阻止

**紧急恢复**:
```bash
# 方法1: 通过控制台
sudo netxfw allow add <your-ip>

# 方法2: 直接操作 BPF Map
sudo bpftool map update name whitelist key <IP> value 1

# 方法3: 停止防火墙
sudo netxfw stop

# 方法4: 删除 BPF 程序
sudo ip link set dev eth0 xdp off
```

### 连接跟踪问题

**问题**: 连接无法建立或断开

**诊断步骤**:
```bash
# 查看连接跟踪数量
sudo netxfw conntrack count

# 查看特定 IP 的连接
sudo netxfw conntrack list | grep <IP>

# 清理过期连接
sudo netxfw conntrack flush --expired
```

---

## 守护进程问题

### 守护进程无法启动

**诊断步骤**:
```bash
# 检查进程状态
sudo systemctl status netxfw

# 查看启动日志
sudo journalctl -u netxfw -n 100

# 检查 PID 文件
ls -la /var/run/netxfw.pid

# 检查端口占用
sudo netstat -tlnp | grep 11811
```

**常见问题**:

| 问题 | 解决方案 |
|------|----------|
| PID 文件存在 | `sudo rm /var/run/netxfw.pid` |
| 端口被占用 | `sudo lsof -i :11811` 然后 kill |
| 配置错误 | `sudo netxfw validate` |
| 权限问题 | `sudo chown -R root:root /etc/netxfw` |

### 守护进程崩溃

**诊断步骤**:
```bash
# 查看核心转储
sudo coredumpctl list netxfw
sudo coredumpctl info <ID>

# 查看系统日志
sudo dmesg | grep -i netxfw

# 检查内存限制
cat /proc/$(pgrep netxfw)/limits | grep memory
```

### 守护进程无响应

**诊断步骤**:
```bash
# 检查进程状态
sudo kill -0 $(cat /var/run/netxfw.pid) && echo "Running" || echo "Not running"

# 检查 goroutine 堆栈
sudo kill -USR1 $(cat /var/run/netxfw.pid)

# 查看堆栈输出
cat /var/log/netxfw/stack.log
```

---

## 调试模式

### 启用调试模式

```bash
# 启动时启用调试
sudo netxfw start --debug

# 或在配置文件中
log:
  level: debug
```

### 使用 bpftool 调试

```bash
# 列出所有 BPF 程序
sudo bpftool prog list

# 查看 XDP 程序详情
sudo bpftool prog show xdp

# 跟踪 BPF 程序执行
sudo bpftool prog tracelog

# 查看 BPF 帮助函数
sudo bpftool feature | grep helper
```

### 使用 bpftrace 调试

```bash
# 跟踪 XDP 程序入口
sudo bpftrace -e 'kprobe:xdp_generic_pass { @[comm] = count(); }'

# 跟踪丢包
sudo bpftrace -e 'kprobe:xdp_drop { @[comm] = count(); }'
```

---

## 联系支持

如果以上方法无法解决问题，请：

1. 收集诊断信息：
```bash
# 收集系统信息
sudo netxfw debug --collect-info > debug_info.tar.gz
```

2. 提交 Issue：https://github.com/netxfw/netxfw/issues

3. 包含以下信息：
   - 系统版本 (`uname -a`)
   - netxfw 版本 (`netxfw version`)
   - 错误日志 (`/var/log/netxfw/error.log`)
   - 配置文件 (`/etc/netxfw/config.yaml`)
   - 复现步骤
