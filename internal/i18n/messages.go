// Package i18n provides i18n functionality.
package i18n

import (
	"fmt"
)

const (
	ErrInvalidIP       = "invalid IP address / 无效的 IP 地址"
	ErrInvalidCIDR     = "invalid CIDR notation / 无效的 CIDR 表示法"
	ErrInvalidPort     = "invalid port number / 无效的端口号"
	ErrInvalidTTL      = "invalid TTL value / 无效的 TTL 值"
	ErrInvalidRate     = "invalid rate limit value / 无效的限速值"
	ErrInvalidBurst    = "invalid burst value / 无效的突发值"
	ErrInvalidAction   = "invalid action / 无效的操作"
	ErrInvalidProtocol = "invalid protocol / 无效的协议"
	ErrInvalidFilePath = "invalid file path / 无效的文件路径"
	ErrInvalidConfig   = "invalid configuration / 无效的配置"

	ErrFileNotFound     = "file not found / 文件未找到"
	ErrFileTooLarge     = "file too large / 文件过大"
	ErrPermissionDenied = "permission denied / 权限被拒绝"
	ErrConfigNotFound   = "config not found / 配置未找到"
	ErrMapNotFound      = "BPF map not found / BPF Map 未找到"
	ErrMapOperation     = "BPF map operation failed / BPF Map 操作失败"
	ErrXDPLoadFailed    = "XDP program load failed / XDP 程序加载失败"
	ErrXDPAttachFailed  = "XDP program attach failed / XDP 程序挂载失败"

	ErrDaemonNotRunning     = "daemon not running / 守护进程未运行"
	ErrDaemonAlreadyRunning = "daemon already running / 守护进程已在运行"
	ErrTimeout              = "operation timeout / 操作超时"
	ErrCanceled             = "operation canceled / 操作已取消"
	ErrNotImplemented       = "not implemented / 未实现"
)

const (
	InfoServiceStarted   = "service started / 服务已启动"
	InfoServiceStopped   = "service stopped / 服务已停止"
	InfoOperationSuccess = "operation succeeded / 操作成功"
	InfoConfigLoaded     = "configuration loaded / 配置已加载"
	InfoConfigSaved      = "configuration saved / 配置已保存"
	InfoIPBlocked        = "IP blocked at XDP layer / IP 已在 XDP 层封禁"
	InfoIPAllowed        = "IP allowed at XDP layer / IP 已在 XDP 层放行"
	InfoIPUnblocked      = "IP unblocked / IP 已解封"
)

const (
	WarnDeprecated      = "deprecated command, use '%s' instead / 旧命令，请使用 '%s'"
	WarnConfigChanged   = "configuration changed, restart required / 配置已更改，需要重启"
	WarnHighMemoryUsage = "high memory usage detected / 检测到高内存使用"
	WarnSlowOperation   = "slow operation detected / 检测到慢操作"
	WarnRateLimitHit    = "rate limit reached / 已达到速率限制"
)

const (
	HelpIPFormat   = "must be <ip>[:port], e.g., 1.2.3.4:8080 or [2001:db8::1]:8080 / 必须是 <ip>[:port]，例如: 1.2.3.4:8080 或 [2001:db8::1]:8080"
	HelpIPv6Format = "IPv6 address must be wrapped in brackets, e.g., [2001:db8::1]:8080 / IPv6 地址必须使用方括号包裹，例如: [2001:db8::1]:8080"
	HelpCIDRFormat = "must be valid CIDR notation, e.g., 192.168.1.0/24 / 必须是有效的 CIDR 表示法，例如: 192.168.1.0/24"
	HelpPortRange  = "port must be between 1-65535 / 端口必须在 1-65535 之间"
	HelpTTLFormat  = "TTL must be a valid duration, e.g., 1h, 30m, 1d / TTL 必须是有效的时间长度，例如: 1h, 30m, 1d"
)

func FormatError(msg string, args ...interface{}) string {
	if len(args) == 0 {
		return msg
	}
	return msg + ": " + formatArgs(args...)
}

func formatArgs(args ...interface{}) string {
	result := ""
	for i, arg := range args {
		if i > 0 {
			result += ", "
		}
		result += formatArg(arg)
	}
	return result
}

func formatArg(arg interface{}) string {
	switch v := arg.(type) {
	case string:
		return v
	case int:
		return fmt.Sprintf("%d", v)
	case int32:
		return fmt.Sprintf("%d", v)
	case int64:
		return fmt.Sprintf("%d", v)
	case uint:
		return fmt.Sprintf("%d", v)
	case uint32:
		return fmt.Sprintf("%d", v)
	case uint64:
		return fmt.Sprintf("%d", v)
	default:
		return fmt.Sprintf("%v", v)
	}
}
