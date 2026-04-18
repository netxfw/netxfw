package common

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	domainrule "github.com/netxfw/netxfw/internal/domain/rule"
)

const (
	// MinPort 最小端口号
	// MinPort minimum port number
	MinPort = domainrule.MinPort

	// MaxPort 最大端口号
	// MaxPort maximum port number
	MaxPort = domainrule.MaxPort

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
	MinTTLSeconds = domainrule.MinTTLSeconds

	// MaxTTLSeconds 最大 TTL 秒数（365 天）
	// MaxTTLSeconds maximum TTL in seconds (365 days)
	MaxTTLSeconds = domainrule.MaxTTLSeconds
)

// ValidateIP 验证 IP 地址格式（支持 IPv4/IPv6/CIDR）
// ValidateIP validates IP address format (supports IPv4/IPv6/CIDR)
// 返回 nil 表示验证通过，否则返回错误信息
// Returns nil if valid, otherwise returns error
func ValidateIP(ip string) error {
	return unwrapRuleValidationError(domainrule.ValidateIP(ip))
}

// ValidatePort 验证端口号范围（0-65535，允许 0 表示无端口）
// ValidatePort validates port number range (0-65535, 0 means no port)
// 返回 nil 表示验证通过，否则返回错误信息
// Returns nil if valid, otherwise returns error
func ValidatePort(port int) error {
	return unwrapRuleValidationError(domainrule.ValidatePort(port, true))
}

// IsValidPort 验证端口号范围（0-65535），返回布尔值
// IsValidPort validates port number range (0-65535), returns boolean
// 用于文件导入等场景，需要静默验证
// Used for file import scenarios where silent validation is needed
func IsValidPort(port int) bool {
	return domainrule.IsValidPort(port)
}

// ValidatePortNonZero 验证端口号范围（1-65535，不允许 0）
// ValidatePortNonZero validates port number range (1-65535, 0 not allowed)
// 返回 nil 表示验证通过，否则返回错误信息
// Returns nil if valid, otherwise returns error
func ValidatePortNonZero(port int) error {
	return unwrapRuleValidationError(domainrule.ValidatePort(port, false))
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
	return domainrule.ValidateRateLimit(rate, burst)
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
	return domainrule.ParseTTL(ttlStr)
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

func unwrapRuleValidationError(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	if idx := strings.Index(msg, "[ERROR]"); idx >= 0 {
		return fmt.Errorf("%s", msg[idx:])
	}
	return err
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
