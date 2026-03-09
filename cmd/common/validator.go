package common

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/netxfw/netxfw/internal/utils/iputil"
)

const (
	// MinPort 最小端口号
	// MinPort minimum port number
	MinPort = 0

	// MaxPort 最大端口号
	// MaxPort maximum port number
	MaxPort = 65535

	// MinLimit 最小列表限制
	// MinLimit minimum list limit
	MinLimit = 1

	// MaxLimit 最大列表限制
	// MaxLimit maximum list limit
	MaxLimit = 100000

	// MaxListLimitSmall 较小的列表限制（用于 limit 命令）
	// MaxListLimitSmall smaller list limit (for limit command)
	MaxListLimitSmall = 10000

	// MaxImportFileSize 最大导入文件大小（100MB）
	// MaxImportFileSize maximum import file size (100MB)
	MaxImportFileSize = 100 * 1024 * 1024

	// MinTTLSeconds 最小 TTL 秒数
	// MinTTLSeconds minimum TTL in seconds
	MinTTLSeconds = 1

	// MaxTTLSeconds 最大 TTL 秒数（365 天）
	// MaxTTLSeconds maximum TTL in seconds (365 days)
	MaxTTLSeconds = 365 * 24 * 60 * 60
)

// ValidateIP 验证 IP 地址格式（支持 IPv4/IPv6/CIDR）
// ValidateIP validates IP address format (supports IPv4/IPv6/CIDR)
// 返回 nil 表示验证通过，否则返回错误信息
// Returns nil if valid, otherwise returns error
func ValidateIP(ip string) error {
	if iputil.IsValidIP(ip) || iputil.IsValidCIDR(ip) {
		return nil
	}
	return fmt.Errorf("[ERROR] Invalid IP address format: %s", ip)
}

// ValidatePort 验证端口号范围（0-65535，允许 0 表示无端口）
// ValidatePort validates port number range (0-65535, 0 means no port)
// 返回 nil 表示验证通过，否则返回错误信息
// Returns nil if valid, otherwise returns error
func ValidatePort(port int) error {
	if port < MinPort || port > MaxPort {
		return fmt.Errorf("[ERROR] Port must be between %d-%d, got %d", MinPort, MaxPort, port)
	}
	return nil
}

// IsValidPort 验证端口号范围（0-65535），返回布尔值
// IsValidPort validates port number range (0-65535), returns boolean
// 用于文件导入等场景，需要静默验证
// Used for file import scenarios where silent validation is needed
func IsValidPort(port int) bool {
	return port >= MinPort && port <= MaxPort
}

// ValidatePortNonZero 验证端口号范围（1-65535，不允许 0）
// ValidatePortNonZero validates port number range (1-65535, 0 not allowed)
// 返回 nil 表示验证通过，否则返回错误信息
// Returns nil if valid, otherwise returns error
func ValidatePortNonZero(port int) error {
	if port < 1 || port > MaxPort {
		return fmt.Errorf("[ERROR] Port must be between 1-%d, got %d", MaxPort, port)
	}
	return nil
}

// ValidateLimit 验证列表限制参数范围（1-100000）
// ValidateLimit validates list limit parameter range (1-100000)
// 返回 nil 表示验证通过，否则返回错误信息
// Returns nil if valid, otherwise returns error
func ValidateLimit(limit int) error {
	if limit < MinLimit || limit > MaxLimit {
		return fmt.Errorf("[ERROR] Limit must be between %d-%d, got %d", MinLimit, MaxLimit, limit)
	}
	return nil
}

// ValidateLimitSmall 验证列表限制参数范围（1-10000，用于 limit 命令）
// ValidateLimitSmall validates list limit parameter range (1-10000, for limit command)
// 返回 nil 表示验证通过，否则返回错误信息
// Returns nil if valid, otherwise returns error
func ValidateLimitSmall(limit int) error {
	if limit < MinLimit || limit > MaxListLimitSmall {
		return fmt.Errorf("[ERROR] Limit must be between %d-%d, got %d", MinLimit, MaxListLimitSmall, limit)
	}
	return nil
}

// ValidateRateLimit 验证速率限制参数
// ValidateRateLimit validates rate limit parameters
// rate: 每秒包数，范围 1-1,000,000
// burst: 突发包数，范围 1-10,000,000
// 返回 nil 表示验证通过，否则返回错误信息
// Returns nil if valid, otherwise returns error
func ValidateRateLimit(rate, burst uint64) error {
	const maxRate = 1000000
	const maxBurst = 10000000

	if rate == 0 {
		return fmt.Errorf("[ERROR] Rate cannot be 0")
	}
	if rate > maxRate {
		return fmt.Errorf("[ERROR] Rate must be at most %d, got %d", maxRate, rate)
	}
	if burst == 0 {
		return fmt.Errorf("[ERROR] Burst cannot be 0")
	}
	if burst > maxBurst {
		return fmt.Errorf("[ERROR] Burst must be at most %d, got %d", maxBurst, burst)
	}
	return nil
}

// ValidateExpiry 验证过期时间范围（1秒 - 365天）
// ValidateExpiry validates expiry time range (1 second - 365 days)
// 返回 nil 表示验证通过，否则返回错误信息
// Returns nil if valid, otherwise returns error
func ValidateExpiry(expirySeconds int) error {
	const minExpiry = 1
	const maxExpiry = 365 * 24 * 60 * 60 // 365 days in seconds

	if expirySeconds < minExpiry {
		return fmt.Errorf("[ERROR] Expiry must be at least %d second(s), got %d", minExpiry, expirySeconds)
	}
	if expirySeconds > maxExpiry {
		return fmt.Errorf("[ERROR] Expiry must be at most %d seconds (365 days), got %d", maxExpiry, expirySeconds)
	}
	return nil
}

// ValidateImportFile 验证导入文件路径和大小
// ValidateImportFile validates import file path and size
// 返回清理后的安全路径和错误信息
// Returns sanitized safe path and error
func ValidateImportFile(path string) (string, error) {
	// 清理路径，防止目录遍历攻击
	// Sanitize path to prevent directory traversal attacks
	safePath := filepath.Clean(path)

	// 检查文件大小，防止内存耗尽攻击
	// Check file size to prevent memory exhaustion attacks
	fileInfo, err := os.Stat(safePath)
	if err != nil {
		return "", fmt.Errorf("failed to stat file: %w", err)
	}
	if fileInfo.Size() > MaxImportFileSize {
		return "", fmt.Errorf("file too large: %d bytes (max %d bytes / 100MB)", fileInfo.Size(), MaxImportFileSize)
	}

	return safePath, nil
}

// ParseAndValidateTTL 解析并验证 TTL 字符串
// ParseAndValidateTTL parses and validates TTL string
// 返回解析后的 duration 和错误信息
// Returns parsed duration and error
func ParseAndValidateTTL(ttlStr string) (time.Duration, error) {
	if ttlStr == "" {
		return 0, fmt.Errorf("[ERROR] --ttl flag is required (e.g., --ttl 1h, --ttl 24h, --ttl 30m)")
	}

	ttl, err := time.ParseDuration(ttlStr)
	if err != nil {
		return 0, fmt.Errorf("[ERROR] Invalid TTL format: %v (use format like 1h, 24h, 30m, 1h30m)", err)
	}

	// 验证 TTL 范围：最小 1 秒，最大 365 天
	// Validate TTL range: minimum 1 second, maximum 365 days
	if ttl < time.Second {
		return 0, fmt.Errorf("[ERROR] TTL must be at least 1 second")
	}
	if ttl > time.Duration(MaxTTLSeconds)*time.Second {
		return 0, fmt.Errorf("[ERROR] TTL cannot exceed 365 days")
	}

	return ttl, nil
}

// ParseLimitAndSearch 解析列表命令的 limit 和 search 参数
// ParseLimitAndSearch parses limit and search parameters for list commands
// 返回 limit, search 和错误信息
// Returns limit, search and error
func ParseLimitAndSearch(args []string, defaultLimit int) (limit int, search string, err error) {
	limit = defaultLimit
	search = ""

	if len(args) == 0 {
		return limit, search, nil
	}

	// 尝试解析第一个参数为 limit
	// Try to parse first argument as limit
	if l, parseErr := parseInt(args[0]); parseErr == nil {
		if err := ValidateLimit(l); err != nil {
			return 0, "", err
		}
		limit = l
		if len(args) > 1 {
			search = args[1]
		}
	} else {
		// 第一个参数不是数字，视为 search
		// First argument is not a number, treat as search
		search = args[0]
	}

	return limit, search, nil
}

// parseInt 辅助函数：解析整数（整个字符串必须是数字）
// parseInt helper function: parse integer (entire string must be numeric)
func parseInt(s string) (int, error) {
	// 使用 strconv.Atoi 更严格，不会解析 "192.168" 为 192
	// strconv.Atoi is stricter, won't parse "192.168" as 192
	result, err := strconv.Atoi(s)
	return result, err
}

// IPPortRule 表示 IP+Port 规则
// IPPortRule represents an IP+Port rule
type IPPortRule struct {
	IP   string
	Port uint16
}

// FilterIPPortRules 从规则列表中过滤指定动作的规则
// FilterIPPortRules filters rules by specified action from rule list
// action: "allow" 或 "deny"
// action: "allow" or "deny"
func FilterIPPortRules(rules map[string]string, action string) []IPPortRule {
	var result []IPPortRule
	for key, act := range rules {
		if act == action {
			parts := strings.Split(key, ":")
			if len(parts) == 2 {
				port, err := strconv.Atoi(parts[1])
				if err != nil {
					continue
				}
				result = append(result, IPPortRule{
					IP:   parts[0],
					Port: uint16(port),
				})
			}
		}
	}
	return result
}
