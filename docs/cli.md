# 命令行手册 (CLI Manual)

`netxfw` 提供了一个简单的命令行界面，用于管理防火墙服务和操作 IP 锁定列表。

## 命令概览

| 命令 | 参数 | 描述 |
| :--- | :--- | :--- |
| `load xdp` | 无 | 启动服务，加载 BPF 程序到网卡 |
| `lock` | `<IP/CIDR>` | 将指定 IP 或网段加入锁定列表 |
| `unlock` | `<IP/CIDR>` | 从锁定列表中移除指定 IP 或网段 |
| `allow` | `<IP/CIDR>` | 将指定 IP 或网段加入白名单 |
| `unallow` | `<IP/CIDR>` | 从白名单中移除指定 IP 或网段 |
| `list` | 无 | 查看当前锁定列表中的 IP 及其丢包统计 |
| `allow-list` | 无 | 查看当前白名单中的 IP 列表 |
| `import` | `<FILE>` | 从文件批量导入 IP 到锁定列表 |
| `unload xdp` | 无 | 提示如何卸载程序 |

---

## 详细说明

### 1. 启动服务 (load xdp)
启动主进程，它会执行以下操作：
- 加载 eBPF 字节码到内核。
- 自动识别系统中的所有物理网卡。
- 将 XDP 程序挂载到这些网卡。
- 在 `/sys/fs/bpf/netxfw` 固定 Map 以供外部控制。
- 启动 Prometheus 指标服务 (默认端口 :9100)。

```bash
sudo ./netxfw load xdp
```

### 2. 封禁 IP (lock)
实时向正在运行的防火墙添加封禁规则。
- 支持标准 IPv4 地址 (如 `192.168.1.1`)。
- 支持标准 IPv6 地址 (如 `2001:db8::1`)。

```bash
sudo ./netxfw lock 1.1.1.1
sudo ./netxfw lock 2400:3200::1
```

### 3. 查看列表 (list)
列出当前内核中生效的所有锁定列表 IP，并显示每个 IP 触发的丢包总数。

```bash
sudo ./netxfw list
```
**输出示例：**
```text
🛡️ Currently locked IPs and drop counts:
 - [IPv4] 1.1.1.1: 42 drops
 - [IPv6] 2400:3200::1: 156 drops
```

### 4. 解封 IP (unlock)
从内核 Map 中删除指定 IP，立即恢复其通信。

```bash
sudo ./netxfw unlock 1.1.1.1
```

### 5. 白名单操作 (allow/unallow/allow-list)
管理白名单，白名单中的 IP 将绕过所有封禁规则。
- `allow`: 添加到白名单。
- `unallow`: 从白名单移除。
- `allow-list`: 查看当前白名单。

```bash
sudo ./netxfw allow 192.168.1.0/24
sudo ./netxfw allow-list
sudo ./netxfw unallow 192.168.1.0/24
```

### 6. 批量导入 (import)
从文本文件中批量读取 IP 或 CIDR 并加入锁定列表。

```bash
sudo ./netxfw import ips.txt
```
