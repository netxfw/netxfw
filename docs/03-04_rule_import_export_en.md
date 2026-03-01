# Rule Import/Export Feature

## 📋 Overview

`netxfw` provides powerful rule import/export functionality supporting multiple formats for different use cases:

- **Text Format**: Simple and easy to use, suitable for manual editing
- **JSON/YAML Format**: Structured data, suitable for backup and version control
- **CSV Format**: Tabular format, suitable for data analysis
- **Binary (.bin.zst) Format**: High-performance binary format, suitable for large-scale rule storage

## 📥 Rule Import

### Command Syntax

```bash
netxfw rule import <type> <file>
```

### Supported Types

| Type | Description | Example |
|------|-------------|---------|
| `lock`/`deny` | Import blacklist rules | `netxfw rule import lock blacklist.txt` |
| `allow` | Import whitelist rules | `netxfw rule import allow whitelist.txt` |
| `rules` | Import IP+Port rules | `netxfw rule import rules ipport.txt` |
| `all` | Import all rule types | `netxfw rule import all rules.json` |
| `binary` | Import binary format blacklist | `netxfw rule import binary rules.deny.bin.zst` |

### File Format Details

#### 1. Text Format

**Blacklist/Whitelist Format**:
```
# This is a comment
192.168.1.100
10.0.0.1
2001:db8::1
192.168.1.0/24
```

**IP+Port Rules Format**:
```
192.168.1.100:80:deny
10.0.0.1:443:allow
2001:db8::1:8080:deny
```

#### 2. JSON/YAML Format

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

#### 3. CSV Format

```csv
type,ip,port,action
blacklist,192.168.1.100,,
whitelist,127.0.0.1,,
ipport,192.168.1.100,80,deny
ipport,10.0.0.1,443,allow
```

#### 4. Binary (.bin.zst) Format

- High-performance binary format
- Uses zstd compression
- Supports blacklist rules only
- Ideal for large-scale rule storage and fast import/export

## 📤 Rule Export

### Command Syntax

```bash
netxfw rule export <file> [--format <format>]
```

### Supported Formats

| Format | Description | Usage |
|--------|-------------|-------|
| `json` | JSON format | `--format json` or file extension `.json` |
| `yaml` | YAML format | `--format yaml` or file extension `.yaml`/`.yml` |
| `csv` | CSV format | `--format csv` or file extension `.csv` |
| `binary` | Binary format | `--format binary` or file extension `.bin.zst` |

### Examples

```bash
# Export as JSON format
netxfw rule export rules.json

# Export as YAML format
netxfw rule export rules.yaml --format yaml

# Export as CSV format
netxfw rule export rules.csv --format csv

# Export as Binary format
netxfw rule export rules.deny.bin.zst --format binary

# Auto-detect format (based on file extension)
netxfw rule export rules.json
netxfw rule export rules.yaml
netxfw rule export rules.csv
netxfw rule export rules.deny.bin.zst
```

## ⚡ Performance Comparison

| Format | Pros | Cons | Use Cases |
|--------|------|------|-----------|
| **Text** | Simple, human-readable, easy to edit | Limited functionality, single rule type only | Quick addition of few IPs |
| **JSON/YAML** | Structured, includes all rule types, readable | Larger file size, slower parsing | Config backup, version control |
| **CSV** | Tabular format, easy to edit in Excel | Large file size, no complex structure support | Data exchange, reporting |
| **Binary** | High performance, high compression ratio, fast parsing | Not human-readable, blacklist only | Large-scale rule storage, fast migration |

## 📋 Best Practices

### 1. Daily Backup

Use JSON or YAML format for regular backups:

```bash
# Regular backup of rules
netxfw rule export /backup/rules-$(date +%Y%m%d).json
```

### 2. Large-Scale Migration

Use Binary format for large-scale rule migration:

```bash
# Export all blacklist rules
netxfw rule export all-rules.bin.zst --format binary

# Import on another machine
netxfw rule import binary all-rules.bin.zst
```

### 3. Batch Import

Use Text format for batch import:

```bash
# Batch import IPs from file
netxfw rule import lock /path/to/blacklist.txt
```

### 4. Data Analysis

Use CSV format for data analysis:

```bash
# Export as CSV for analysis in Excel
netxfw rule export rules.csv --format csv
```

## 🛠️ Troubleshooting

### Common Issues

1. **File Format Errors**:
   - Ensure file extension is correct
   - Check file encoding is UTF-8
   - Verify JSON/YAML format is valid

2. **Permission Issues**:
   - Ensure read/write permissions on target file
   - Run command with `sudo`

3. **Path Issues**:
   - Use absolute or relative paths
   - Avoid special characters and spaces

### Debug Tips

```bash
# View detailed help
netxfw rule import --help
netxfw rule export --help

# Check import results
netxfw list

# View current status
netxfw status
```

## 📚 Related Documents

- [CLI Manual](./cli/cli_en.md)
- [Advanced Configuration Guide](./config_management_unification.md)
- [Performance Benchmarks](./performance/benchmarks_en.md)