# NetXFW 国际化策略

## 概述

NetXFW 采用**中英文双语策略**，在代码注释、错误信息和用户界面中同时提供中文和英文支持。

## 设计原则

### 1. 双语注释

所有代码注释采用中英文双语格式：

```go
// InstallXDP initializes the XDP manager and mounts the program to interfaces, then exits.
// InstallXDP 初始化 XDP 管理器并将程序挂载到接口，然后退出。
func InstallXDP(ctx context.Context, cliInterfaces []string) error {
    // ...
}
```

### 2. 用户界面双语

CLI 命令的帮助信息和错误提示提供双语支持：

```go
Long: `Allow IP at XDP layer (add to whitelist).
支持 IPv4: 1.2.3.4:8080
支持 IPv6: [2001:db8::1]:8080`,
```

### 3. 错误信息格式

错误信息采用统一的格式：

```go
// ✅ 推荐：双语错误信息
return fmt.Errorf("invalid input format, must be <ip>[:port] / 无效的输入格式，必须是 <ip>[:port]")

// ✅ 推荐：带上下文的错误信息
return fmt.Errorf("[ERROR] Failed to list blocked IPs: %v", err)

// ❌ 避免：纯中文错误信息
return fmt.Errorf("无效的 IP 地址")
```

## 实现指南

### 1. 错误信息格式化

使用统一的错误信息格式：

```go
// 英文在前，中文在后，用 " / " 分隔
const (
    ErrInvalidIPFormat = "invalid IP format / 无效的 IP 格式"
    ErrInvalidPort     = "invalid port number / 无效的端口号"
    ErrNotFound        = "resource not found / 资源未找到"
)
```

### 2. 日志信息格式化

日志信息也采用双语格式：

```go
log.Infof("[START] XDP program installed successfully / XDP 程序安装成功")
log.Warnf("[WARN]  Failed to load BPF plugins: %v / 加载 BPF 插件失败: %v", err)
```

### 3. CLI 输出格式化

CLI 输出提供双语提示：

```go
cmd.Println("=== Blocked IPs ===")
cmd.Println("[INFO] Total: %d IPs")
cmd.Println("[TIP] Use --limit 0 to show all / 使用 --limit 0 显示全部")
```

## 工具支持

### 1. 错误信息检查工具

使用以下命令检查错误信息格式：

```bash
# 检查中文错误信息
grep -r "fmt\.Errorf.*[\u4e00-\u9fa5]" --include="*.go" | grep -v "_test.go"

# 检查双语格式
grep -r " / " --include="*.go" | grep "fmt\.Errorf"
```

### 2. 自动格式化工具

创建 `scripts/format_i18n.sh`：

```bash
#!/bin/bash
# 格式化错误信息，确保双语格式

find . -name "*.go" -not -path "./vendor/*" -exec grep -l "fmt\.Errorf" {} \; | while read file; do
    echo "Checking: $file"
    # 检查是否包含中文但没有英文
    if grep -q "fmt\.Errorf.*[\u4e00-\u9fa5]" "$file" && ! grep -q " / " "$file"; then
        echo "Warning: Found Chinese-only error messages in $file"
    fi
done
```

## 最佳实践

### 1. 新增错误信息

```go
// ✅ 推荐
if err := validateIP(ip); err != nil {
    return fmt.Errorf("invalid IP address: %s / 无效的 IP 地址: %s", ip, ip)
}

// ❌ 避免
if err := validateIP(ip); err != nil {
    return fmt.Errorf("无效的 IP 地址: %s", ip)
}
```

### 2. 错误信息模板

创建 `internal/i18n/messages.go`：

```go
package i18n

const (
    // Error messages
    ErrInvalidIP      = "invalid IP address / 无效的 IP 地址"
    ErrInvalidCIDR    = "invalid CIDR notation / 无效的 CIDR 表示法"
    ErrInvalidPort    = "invalid port number / 无效的端口号"
    ErrNotFound       = "resource not found / 资源未找到"
    ErrPermission     = "permission denied / 权限被拒绝"
    ErrTimeout        = "operation timeout / 操作超时"
    
    // Info messages
    InfoStarted       = "service started / 服务已启动"
    InfoStopped       = "service stopped / 服务已停止"
    InfoSuccess       = "operation succeeded / 操作成功"
    
    // Warning messages
    WarnDeprecated    = "deprecated command, use '%s' instead / 旧命令，请使用 '%s'"
    WarnConfigChange  = "configuration changed / 配置已更改"
)
```

### 3. 使用错误信息模板

```go
import "github.com/netxfw/netxfw/internal/i18n"

func validateIP(ip string) error {
    if net.ParseIP(ip) == nil {
        return fmt.Errorf("%s: %s", i18n.ErrInvalidIP, ip)
    }
    return nil
}
```

## 统计数据

### 当前状态

- **中文注释**: 2,356 处（100 个文件）
- **中文错误信息**: 2 个文件
- **双语格式**: 已在大部分文件中实现

### 目标

- ✅ 所有代码注释采用双语格式
- ✅ 所有用户界面提供双语支持
- ✅ 所有错误信息采用统一格式
- ⏳ 创建错误信息模板库（可选）

## 国际化策略

### 1. 当前策略：双语支持

**优点**：
- 用户无需切换语言
- 降低国际化复杂度
- 适合中文用户群体

**缺点**：
- 信息量增加
- 可能影响代码可读性

### 2. 未来策略：完整国际化（可选）

如果需要支持更多语言，可以采用以下方案：

```go
package i18n

type Language string

const (
    LangEN Language = "en"
    LangZH Language = "zh"
)

var messages = map[Language]map[string]string{
    LangEN: {
        "err.invalid_ip": "invalid IP address",
        "err.invalid_port": "invalid port number",
    },
    LangZH: {
        "err.invalid_ip": "无效的 IP 地址",
        "err.invalid_port": "无效的端口号",
    },
}

func GetMessage(lang Language, key string) string {
    if msgs, ok := messages[lang]; ok {
        return msgs[key]
    }
    return key
}
```

## 相关文件

- [cmd/agent/simple_list.go](../cmd/agent/simple_list.go) - CLI 双语示例
- [tools/yaml2toml/main.go](../tools/yaml2toml/main.go) - 工具双语示例
- [internal/api/auth.go](../internal/api/auth.go) - API 双语注释示例

## 参考资料

- [Go 国际化最佳实践](https://go.dev/blog/i18n)
- [CLI 设计指南](https://clig.dev/)
- [错误信息设计](https://medium.com/@xoen/error-messages-design-3d1f11c9d52b)
