# netxfw 命令列表

## 📋 核心命令

| 命令 | 说明 | 别名 |
|------|------|------|
| `netxfw status` | 查看防火墙运行状态 | - |
| `netxfw start` | 启动防火墙 | `enable` |
| `netxfw stop` | 停止防火墙 | `disable` |
| `netxfw reload` | 重载配置（不重启 XDP） | - |
| `netxfw version` | 查看版本信息 | - |

## 🔒 封禁管理命令

| 命令 | 说明 | 别名 |
|------|------|------|
| `netxfw block <ip>` | 在 XDP 层封禁 IP（永久） | `deny` |
| `netxfw block <ip> -d 1h` | 临时封禁 IP（1小时后自动解封） | - |
| `netxfw unblock <ip>` | 解封 IP | `delete` |
| `netxfw list` | 查看所有封禁的 IP | - |
| `netxfw list --static` | 只查看永久封禁的 IP | - |
| `netxfw list --dynamic` | 只查看临时封禁的 IP | - |
| `netxfw clear` | 清空所有封禁的 IP | - |
| `netxfw reset` | 重置防火墙（清空所有封禁） | - |

## 📊 status 命令选项

| 选项 | 说明 |
|------|------|
| `-v, --verbose` | 显示详细状态信息 |

## 📖 命令使用示例

### 查看状态
```bash
# 查看简单状态
netxfw status

# 查看详细状态
netxfw status -v
```

### 启动/停止防火墙
```bash
# 启动防火墙
netxfw start
# 或使用 ufw 风格
netxfw enable

# 停止防火墙
netxfw stop
# 或使用 ufw 风格
netxfw disable
```

### 封禁 IP
```bash
# 永久封禁 IP
netxfw block 192.168.1.100
# 或使用 ufw 风格
netxfw deny 192.168.1.100

# 临时封禁 1 小时
netxfw block 192.168.1.100 -d 1h

# 临时封禁 30 分钟
netxfw block 192.168.1.100 -d 30m
```

### 解封 IP
```bash
# 解封 IP
netxfw unblock 192.168.1.100
# 或使用 ufw 风格
netxfw delete 192.168.1.100
```

### 查看封禁列表
```bash
# 查看所有封禁的 IP
netxfw list

# 只查看永久封禁
netxfw list --static

# 只查看临时封禁
netxfw list --dynamic
```

### 清空封禁
```bash
# 清空所有封禁的 IP
netxfw clear

# 重置防火墙（会清空所有）
netxfw reset
```

### 重载配置
```bash
# 重载配置（不重启 XDP 程序，保持现有连接）
netxfw reload
```

## 💡 快捷键总结

| 操作 | 命令 |
|------|------|
| 启动 | `netxfw enable` |
| 停止 | `netxfw disable` |
| 封禁 | `netxfw deny <ip>` |
| 解封 | `netxfw delete <ip>` |
| 查看 | `netxfw list` |
| 清空 | `netxfw reset` |

## 🎯 快速入门

1. **启动防火墙**
   ```bash
   netxfw enable
   ```

2. **封禁一个恶意 IP**
   ```bash
   netxfw deny 1.2.3.4
   ```

3. **查看当前封禁**
   ```bash
   netxfw list
   ```

4. **查看状态**
   ```bash
   netxfw status
   ```

5. **停止防火墙**
   ```bash
   netxfw disable
   ```
