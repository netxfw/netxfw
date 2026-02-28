# 规则导入导出功能 (Rule Import/Export Feature)

## 📋 概述 (Overview)

`netxfw` 提供强大的规则导入导出功能，支持多种格式以满足不同的使用场景：

- **文本格式**：简单易用，适合手动编辑
- **JSON/YAML 格式**：结构化数据，适合备份和版本控制
- **CSV 格式**：表格格式，适合数据分析
- **Binary (.bin.zst) 格式**：高性能二进制格式，适合大规模规则存储

## 📥 规则导入 (Rule Import)

### 命令语法 (Command Syntax)

```bash
netxfw rule import <type> <file>
```

### 支持的类型 (Supported Types)

| 类型 (Type) | 说明 (Description) | 示例 (Example) |
|-------------|-------------------|----------------|
| `lock`/`deny` | 导入黑名单规则 | `netxfw rule import lock blacklist.txt` |
| `allow` | 导入白名单规则 | `netxfw rule import allow whitelist.txt` |
| `rules` | 导入 IP+端口规则 | `netxfw rule import rules ipport.txt` |
| `all` | 导入所有规则类型 | `netxfw rule import all rules.json` |
| `binary` | 导入二进制格式黑名单 | `netxfw rule import binary rules.deny.bin.zst` |

### 文件格式说明 (File Format Details)

#### 1. 文本格式 (Text Format)

**黑名单/白名单格式**：
```
# 这是注释
192.168.1.100
10.0.0.1
2001:db8::1
192.168.1.0/24
```

**IP+端口规则格式**：
```
192.168.1.100:80:deny
10.0.0.1:443:allow
2001:db8::1:8080:deny
```

#### 2. JSON/YAML 格式

```json
{
  "blacklist": [
    {"type": "blacklist", "ip": "192.168.1.100"},
    {"type": "blacklist", "ip": "10.0.0.1"}
  ],
  "whitelist": [
    {"type": "whitelist", "ip": "127.0.0.1"},
    {"type": "whitelist", "ip": "10.0.0.0/8"}
  ],
  "ipport": [
    {"type": "ipport", "ip": "192.168.1.100", "port": 80, "action": "deny"},
    {"type": "ipport", "ip": "10.0.0.1", "port": 443, "action": "allow"}
  ]
}
```

#### 3. CSV 格式

```csv
type,ip,port,action
blacklist,192.168.1.100,,
whitelist,127.0.0.1,,
ipport,192.168.1.100,80,deny
ipport,10.0.0.1,443,allow
```

#### 4. Binary (.bin.zst) 格式

- 高性能二进制格式
- 使用 zstd 压缩
- 仅支持黑名单规则
- 适合大规模规则存储和快速导入导出

## 📤 规则导出 (Rule Export)

### 命令语法 (Command Syntax)

```bash
netxfw rule export <file> [--format <format>]
```

### 支持的格式 (Supported Formats)

| 格式 (Format) | 说明 (Description) | 使用方法 (Usage) |
|---------------|-------------------|------------------|
| `json` | JSON 格式 | `--format json` 或文件扩展名 `.json` |
| `yaml` | YAML 格式 | `--format yaml` 或文件扩展名 `.yaml`/`.yml` |
| `csv` | CSV 格式 | `--format csv` 或文件扩展名 `.csv` |
| `binary` | 二进制格式 | `--format binary` 或文件扩展名 `.bin.zst` |

### 示例 (Examples)

```bash
# 导出为 JSON 格式
netxfw rule export rules.json

# 导出为 YAML 格式
netxfw rule export rules.yaml --format yaml

# 导出为 CSV 格式
netxfw rule export rules.csv --format csv

# 导出为 Binary 格式
netxfw rule export rules.deny.bin.zst --format binary

# 自动检测格式（根据文件扩展名）
netxfw rule export rules.json
netxfw rule export rules.yaml
netxfw rule export rules.csv
netxfw rule export rules.deny.bin.zst
```

## ⚡ 性能对比 (Performance Comparison)

| 格式 (Format) | 优点 (Pros) | 缺点 (Cons) | 适用场景 (Use Cases) |
|---------------|-------------|-------------|---------------------|
| **文本** | 简单易读，手动编辑方便 | 功能有限，仅支持单一规则类型 | 快速添加少量 IP |
| **JSON/YAML** | 结构化，包含所有规则类型，易读 | 文件较大，解析较慢 | 配置备份、版本控制 |
| **CSV** | 表格格式，便于 Excel 编辑 | 文件较大，不支持复杂结构 | 数据交换、报表 |
| **Binary** | 高性能，压缩率高，解析快 | 不可读，仅支持黑名单 | 大规模规则存储、快速迁移 |

## 📋 最佳实践 (Best Practices)

### 1. 日常备份 (Daily Backup)

使用 JSON 或 YAML 格式进行定期备份：

```bash
# 定期备份规则
netxfw rule export /backup/rules-$(date +%Y%m%d).json
```

### 2. 大规模迁移 (Large-Scale Migration)

使用 Binary 格式进行大规模规则迁移：

```bash
# 导出所有黑名单
netxfw rule export all-rules.bin.zst --format binary

# 在另一台机器导入
netxfw rule import binary all-rules.bin.zst
```

### 3. 批量导入 (Batch Import)

使用文本格式进行批量导入：

```bash
# 从文件批量导入 IP
netxfw rule import lock /path/to/blacklist.txt
```

### 4. 数据分析 (Data Analysis)

使用 CSV 格式进行数据分析：

```bash
# 导出为 CSV，在 Excel 中分析
netxfw rule export rules.csv --format csv
```

## 🛠️ 故障排除 (Troubleshooting)

### 常见问题 (Common Issues)

1. **文件格式错误**：
   - 确保文件扩展名正确
   - 检查文件编码是否为 UTF-8
   - 验证 JSON/YAML 格式是否正确

2. **权限问题**：
   - 确保对目标文件具有读写权限
   - 使用 `sudo` 运行命令

3. **路径问题**：
   - 使用绝对路径或相对路径
   - 避免特殊字符和空格

### 调试技巧 (Debug Tips)

```bash
# 查看详细帮助
netxfw rule import --help
netxfw rule export --help

# 检查导入结果
netxfw list

# 查看当前状态
netxfw status
```

## 📚 相关文档 (Related Documents)

- [CLI 命令手册](./cli/cli.md)
- [高级配置指南](./config_management_unification.md)
- [性能基准测试](./performance/benchmarks.md)