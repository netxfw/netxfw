# netxfw 命令列表

## 📋 核心命令

| 命令 | 说明 | 别名 |
|------|------|------|
| `netxfw status` | 查看防火墙运行状态 | - |
| `netxfw start` | 启动防火墙 | `enable` |
| `netxfw stop` | 停止防火墙 | `disable` |
| `netxfw reload` | 重载配置（不重启 XDP） | - |
| `netxfw version` | 查看版本信息 | - |
| `netxfw rule import` | 导入规则（支持多种格式） | - |
| `netxfw rule export` | 导出规则（支持多种格式） | - |

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

---

## 📥 规则导入导出命令

### 导入规则

| 命令 | 说明 |
|------|------|
| `netxfw rule import lock <file>` | 导入黑名单规则（文本格式） |
| `netxfw rule import allow <file>` | 导入白名单规则（文本格式） |
| `netxfw rule import rules <file>` | 导入 IP+Port 规则（文本格式） |
| `netxfw rule import all <file>` | 导入所有规则（JSON/TOML 格式） |
| `netxfw rule import binary <file>` | 导入黑名单（Binary.bin.zst 格式） |

### 导出规则

| 命令 | 说明 |
|------|------|
| `netxfw rule export <file>` | 导出所有规则（自动检测格式） |
| `netxfw rule export <file> --format json` | 导出为 JSON 格式 |
| `netxfw rule export <file> --format toml` | 导出为 TOML 格式 |
| `netxfw rule export <file> --format csv` | 导出为 CSV 格式 |
| `netxfw rule export <file> --format binary` | 导出为 Binary.bin.zst 格式 |

### 文件格式说明

#### 1. 文本格式（Text Format）
- **lock/allow**: 每行一个 IP 地址
  ```
  192.168.1.100
  10.0.0.1
  2001:db8::1
  ```
- **rules**: 每行格式为 `IP:Port:Action`
  ```
  192.168.1.100:80:deny
  10.0.0.1:443:allow
  ```

#### 2. JSON/TOML 格式
结构化数据，包含所有规则类型：
```json
{
  "blacklist": [
    {"type": "blacklist", "ip": "192.168.1.100"}
  ],
  "whitelist": [
    {"type": "whitelist", "ip": "10.0.0.1"}
  ],
  "ipport": [
    {"type": "ipport", "ip": "192.168.1.100", "port": 80, "action": "deny"}
  ]
}
```

#### 3. CSV 格式
表格格式，包含表头：
```csv
type,ip,port,action
blacklist,192.168.1.100,,
whitelist,10.0.0.1,,
ipport,192.168.1.100,80,deny
```

#### 4. Binary 格式（.bin.zst）
- 高性能二进制格式
- 使用 zstd 压缩
- 仅支持黑名单规则
- 适合大规模规则存储和快速导入导出

### 使用示例

#### 导入规则
```bash
# 从文本文件导入黑名单
netxfw rule import lock blacklist.txt

# 从文本文件导入白名单
netxfw rule import allow whitelist.txt

# 从文本文件导入 IP+Port 规则
netxfw rule import rules ipport.txt

# 从 JSON 文件导入所有规则
netxfw rule import all rules.json

# 从 TOML 文件导入所有规则
netxfw rule import all rules.toml

# 从 bin.zst 文件导入黑名单
netxfw rule import binary rules.deny.bin.zst
```

#### 导出规则
```bash
# 导出为 JSON 格式
netxfw rule export rules.json

# 导出为 TOML 格式
netxfw rule export rules.toml --format toml

# 导出为 CSV 格式
netxfw rule export rules.csv --format csv

# 导出为 Binary 格式（仅黑名单）
netxfw rule export rules.deny.bin.zst --format binary

# 自动检测格式（根据文件扩展名）
netxfw rule export rules.json
netxfw rule export rules.toml
netxfw rule export rules.csv
netxfw rule export rules.deny.bin.zst
```

### 性能对比

| 格式 | 优点 | 缺点 | 适用场景 |
|------|------|------|----------|
| **文本** | 简单易读，手动编辑方便 | 功能有限，仅支持单一规则类型 | 快速添加少量 IP |
| **JSON/TOML** | 结构化，包含所有规则类型，易读 | 文件较大，解析较慢 | 配置备份、版本控制 |
| **CSV** | 表格格式，便于 Excel 编辑 | 文件较大，不支持复杂结构 | 数据交换、报表 |
| **Binary** | 高性能，压缩率高，解析快 | 不可读，仅支持黑名单 | 大规模规则存储、快速迁移 |

### 最佳实践

1. **日常备份**：使用 JSON 或 YAML 格式
   ```bash
   # 定期备份规则
   netxfw rule export /backup/rules-$(date +%Y%m%d).json
   ```

2. **大规模迁移**：使用 Binary 格式
   ```bash
   # 导出所有黑名单
   netxfw rule export all-rules.bin.zst --format binary
   
   # 在另一台机器导入
   netxfw rule import binary all-rules.bin.zst
   ```

3. **批量导入**：使用文本格式
   ```bash
   # 从文件批量导入 IP
   netxfw rule import lock /path/to/blacklist.txt
   ```

4. **数据分析**：使用 CSV 格式
   ```bash
   # 导出为 CSV，在 Excel 中分析
   netxfw rule export rules.csv --format csv
   ```
