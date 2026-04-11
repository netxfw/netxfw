package types

import (
	"fmt"
	"net"
	"time"

	"github.com/BurntSushi/toml"
)

// ValidationError represents a single validation error.
// ValidationError 表示单个验证错误。
type ValidationError struct {
	Field   string `json:"field"`   // Field path (e.g., "base.icmp_rate")
	Message string `json:"message"` // Error message
	Value   any    `json:"value"`   // The invalid value (optional)
}

// ValidationWarning represents a potential issue that's not critical.
// ValidationWarning 表示非关键的潜在问题。
type ValidationWarning struct {
	Field   string `json:"field"`   // Field path
	Message string `json:"message"` // Warning message
	Value   any    `json:"value"`   // The value causing warning (optional)
}

// ValidationResult contains all validation errors and warnings.
// ValidationResult 包含所有验证错误和警告。
type ValidationResult struct {
	Valid    bool                `json:"valid"`    // Whether the config is valid
	Errors   []ValidationError   `json:"errors"`   // Critical errors
	Warnings []ValidationWarning `json:"warnings"` // Non-critical warnings
}

// AddError adds a validation error.
// AddError 添加验证错误。
func (r *ValidationResult) AddError(field, message string, value any) {
	r.Errors = append(r.Errors, ValidationError{
		Field:   field,
		Message: message,
		Value:   value,
	})
	r.Valid = false
}

// AddWarning adds a validation warning.
// AddWarning 添加验证警告。
func (r *ValidationResult) AddWarning(field, message string, value any) {
	r.Warnings = append(r.Warnings, ValidationWarning{
		Field:   field,
		Message: message,
		Value:   value,
	})
}

// ConfigValidator provides configuration validation functionality.
// ConfigValidator 提供配置验证功能。
type ConfigValidator struct {
	// Max allowed values for range checks / 范围检查的最大允许值
	MaxPort            int
	MaxRate            uint64
	MaxBurst           uint64
	MaxMapCapacity     int
	MaxCleanupInterval time.Duration
	MinCleanupInterval time.Duration
}

// NewConfigValidator creates a new ConfigValidator with default limits.
// NewConfigValidator 创建具有默认限制的新 ConfigValidator。
func NewConfigValidator() *ConfigValidator {
	return &ConfigValidator{
		MaxPort:            65535,
		MaxRate:            10000000, // 10M pps
		MaxBurst:           50000000, // 50M packets
		MaxMapCapacity:     10000000, // 10M entries
		MaxCleanupInterval: 24 * time.Hour,
		MinCleanupInterval: 10 * time.Second,
	}
}

// ValidateSyntax validates the YAML syntax of the configuration.
// ValidateSyntax 验证配置的 YAML 语法。
func (v *ConfigValidator) ValidateSyntax(configData []byte) *ValidationResult {
	result := &ValidationResult{Valid: true, Errors: []ValidationError{}, Warnings: []ValidationWarning{}}

	var rawConfig map[string]any
	if _, err := toml.Decode(string(configData), &rawConfig); err != nil {
		result.AddError("config", fmt.Sprintf("TOML syntax error: %v", err), nil)
		return result
	}

	return result
}

// Validate validates the entire configuration.
// Validate 验证整个配置。
func (v *ConfigValidator) Validate(cfg *GlobalConfig) *ValidationResult {
	result := &ValidationResult{Valid: true, Errors: []ValidationError{}, Warnings: []ValidationWarning{}}

	// Validate each section / 验证每个部分
	v.validateBaseConfig(&cfg.Base, result)
	v.validateWebConfig(&cfg.Web, result)
	v.validateMetricsConfig(&cfg.Metrics, result)
	v.validatePortConfig(&cfg.Port, result)
	v.validateConntrackConfig(&cfg.Conntrack, result)
	v.validateRateLimitConfig(&cfg.RateLimit, result)
	v.validateLogEngineConfig(&cfg.LogEngine, result)
	v.validateCapacityConfig(&cfg.Capacity, result)
	v.validateLoggingConfig(&cfg.Logging, result)

	// Cross-section validation / 跨部分验证
	v.detectConflicts(cfg, result)

	return result
}

// validateBaseConfig validates base configuration.
// validateBaseConfig 验证基础配置。
func (v *ConfigValidator) validateBaseConfig(cfg *BaseConfig, result *ValidationResult) {
	v.validateICMPConfig(cfg, result)
	v.validateCleanupInterval(cfg, result)
	v.validatePprofConfig(cfg, result)
	v.validateWhitelistCIDRs(cfg, result)
	v.validateLockListMasks(cfg, result)
}

// validateICMPConfig validates ICMP rate and burst configuration.
// validateICMPConfig 验证 ICMP 速率和突发量配置。
func (v *ConfigValidator) validateICMPConfig(cfg *BaseConfig, result *ValidationResult) {
	if cfg.ICMPRate > v.MaxRate {
		result.AddError("base.icmp_rate",
			fmt.Sprintf("ICMP rate exceeds maximum allowed value (%d)", v.MaxRate), cfg.ICMPRate)
	}

	if cfg.ICMPBurst > v.MaxBurst {
		result.AddError("base.icmp_burst",
			fmt.Sprintf("ICMP burst exceeds maximum allowed value (%d)", v.MaxBurst), cfg.ICMPBurst)
	}

	if cfg.ICMPBurst > 0 && cfg.ICMPRate > 0 && cfg.ICMPBurst < cfg.ICMPRate {
		result.AddWarning("base.icmp_burst",
			"ICMP burst should be >= rate for proper token bucket behavior", cfg.ICMPBurst)
	}
}

// validateCleanupInterval validates cleanup interval configuration.
// validateCleanupInterval 验证清理间隔配置。
func (v *ConfigValidator) validateCleanupInterval(cfg *BaseConfig, result *ValidationResult) {
	if cfg.CleanupInterval == "" {
		return
	}

	duration, err := time.ParseDuration(cfg.CleanupInterval)
	if err != nil {
		result.AddError("base.cleanup_interval",
			fmt.Sprintf("Invalid duration format: %v", err), cfg.CleanupInterval)
		return
	}

	if duration < v.MinCleanupInterval {
		result.AddWarning("base.cleanup_interval",
			fmt.Sprintf("Cleanup interval is very short (min recommended: %v)", v.MinCleanupInterval), cfg.CleanupInterval)
	}
	if duration > v.MaxCleanupInterval {
		result.AddWarning("base.cleanup_interval",
			fmt.Sprintf("Cleanup interval is very long (max recommended: %v)", v.MaxCleanupInterval), cfg.CleanupInterval)
	}
}

// validatePprofConfig validates pprof configuration.
// validatePprofConfig 验证 pprof 配置。
func (v *ConfigValidator) validatePprofConfig(cfg *BaseConfig, result *ValidationResult) {
	if cfg.EnablePprof && (cfg.PprofPort < 1 || cfg.PprofPort > v.MaxPort) {
		result.AddError("base.pprof_port",
			fmt.Sprintf("Port must be between 1 and %d", v.MaxPort), cfg.PprofPort)
	}
}

// validateWhitelistCIDRs validates whitelist CIDRs.
// validateWhitelistCIDRs 验证白名单 CIDR。
func (v *ConfigValidator) validateWhitelistCIDRs(cfg *BaseConfig, result *ValidationResult) {
	for i, cidr := range cfg.Whitelist {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			if ip := net.ParseIP(cidr); ip == nil {
				result.AddError(fmt.Sprintf("base.whitelist[%d]", i),
					fmt.Sprintf("Invalid IP or CIDR format: %s", cidr), cidr)
			}
		}
	}
}

// validateLockListMasks validates lock list merge threshold and masks.
// validateLockListMasks 验证锁定列表合并阈值和掩码。
func (v *ConfigValidator) validateLockListMasks(cfg *BaseConfig, result *ValidationResult) {
	if cfg.LockListMergeThreshold < 0 {
		result.AddError("base.lock_list_merge_threshold",
			"Merge threshold cannot be negative", cfg.LockListMergeThreshold)
	}

	if cfg.LockListV4Mask < 0 || cfg.LockListV4Mask > 32 {
		result.AddError("base.lock_list_v4_mask",
			"IPv4 mask must be between 0 and 32", cfg.LockListV4Mask)
	}

	if cfg.LockListV6Mask < 0 || cfg.LockListV6Mask > 128 {
		result.AddError("base.lock_list_v6_mask",
			"IPv6 mask must be between 0 and 128", cfg.LockListV6Mask)
	}
}

// validateWebConfig validates web configuration.
// validateWebConfig 验证 Web 配置。
func (v *ConfigValidator) validateWebConfig(cfg *WebConfig, result *ValidationResult) {
	if !cfg.Enabled {
		return
	}

	// Validate port / 验证端口
	if cfg.Port < 1 || cfg.Port > v.MaxPort {
		result.AddError("web.port",
			fmt.Sprintf("Port must be between 1 and %d", v.MaxPort), cfg.Port)
	}

	// Warn about missing token in production / 生产环境缺少 token 的警告
	if cfg.Token == "" {
		result.AddWarning("web.token",
			"Web interface is enabled without authentication token - not recommended for production", nil)
	}
}

// validateMetricsConfig validates metrics configuration.
// validateMetricsConfig 验证指标配置。
func (v *ConfigValidator) validateMetricsConfig(cfg *MetricsConfig, result *ValidationResult) {
	if !cfg.Enabled && !cfg.ServerEnabled {
		return
	}

	// Validate port / 验证端口
	if cfg.Port < 1 || cfg.Port > v.MaxPort {
		result.AddError("metrics.port",
			fmt.Sprintf("Port must be between 1 and %d", v.MaxPort), cfg.Port)
	}

	// Validate push interval / 验证推送间隔
	if cfg.PushEnabled && cfg.PushInterval != "" {
		if _, err := time.ParseDuration(cfg.PushInterval); err != nil {
			result.AddError("metrics.push_interval",
				fmt.Sprintf("Invalid duration format: %v", err), cfg.PushInterval)
		}
	}

	// Validate push gateway address / 验证推送网关地址
	if cfg.PushEnabled && cfg.PushGatewayAddr == "" {
		result.AddError("metrics.push_gateway_addr",
			"Push gateway address is required when push is enabled", nil)
	}
}

// validatePortConfig validates port configuration.
// validatePortConfig 验证端口配置。
func (v *ConfigValidator) validatePortConfig(cfg *PortConfig, result *ValidationResult) {
	// Validate allowed ports / 验证允许的端口
	for i, port := range cfg.AllowedPorts {
		if port < 1 || int(port) > v.MaxPort {
			result.AddError(fmt.Sprintf("port.allowed_ports[%d]", i),
				fmt.Sprintf("Port must be between 1 and %d", v.MaxPort), port)
		}
	}

	// Validate IP-Port rules / 验证 IP-端口规则
	for i, rule := range cfg.IPPortRules {
		fieldPrefix := fmt.Sprintf("port.ip_port_rules[%d]", i)

		// Validate IP/CIDR / 验证 IP/CIDR
		if rule.IP != "" {
			if _, _, err := net.ParseCIDR(rule.IP); err != nil {
				if ip := net.ParseIP(rule.IP); ip == nil {
					result.AddError(fmt.Sprintf("%s.ip", fieldPrefix),
						fmt.Sprintf("Invalid IP or CIDR format: %s", rule.IP), rule.IP)
				}
			}
		}

		// Validate port / 验证端口
		if int(rule.Port) > v.MaxPort {
			result.AddError(fmt.Sprintf("%s.port", fieldPrefix),
				fmt.Sprintf("Port must be between 0 and %d", v.MaxPort), rule.Port)
		}

		// Validate action / 验证动作
		if rule.Action != 0 && rule.Action != 1 && rule.Action != 2 {
			result.AddError(fmt.Sprintf("%s.action", fieldPrefix),
				"Action must be 0/2 (deny) or 1 (allow)", rule.Action)
		}
	}
}

// validateConntrackConfig validates conntrack configuration.
// validateConntrackConfig 验证连接跟踪配置。
func (v *ConfigValidator) validateConntrackConfig(cfg *ConntrackConfig, result *ValidationResult) {
	if !cfg.Enabled {
		return
	}

	// Validate max entries / 验证最大条目数
	if cfg.MaxEntries < 0 {
		result.AddError("conntrack.max_entries",
			"Max entries cannot be negative", cfg.MaxEntries)
	} else if cfg.MaxEntries > v.MaxMapCapacity {
		result.AddWarning("conntrack.max_entries",
			fmt.Sprintf("Max entries is very high (max recommended: %d)", v.MaxMapCapacity), cfg.MaxEntries)
	}

	// Validate TCP timeout / 验证 TCP 超时
	if cfg.TCPTimeout != "" {
		if _, err := time.ParseDuration(cfg.TCPTimeout); err != nil {
			result.AddError("conntrack.tcp_timeout",
				fmt.Sprintf("Invalid duration format: %v", err), cfg.TCPTimeout)
		}
	}

	// Validate UDP timeout / 验证 UDP 超时
	if cfg.UDPTimeout != "" {
		if _, err := time.ParseDuration(cfg.UDPTimeout); err != nil {
			result.AddError("conntrack.udp_timeout",
				fmt.Sprintf("Invalid duration format: %v", err), cfg.UDPTimeout)
		}
	}
}

// validateRateLimitConfig validates rate limit configuration.
// validateRateLimitConfig 验证速率限制配置。
func (v *ConfigValidator) validateRateLimitConfig(cfg *RateLimitConfig, result *ValidationResult) {
	if !cfg.Enabled {
		return
	}

	// Validate auto block expiry / 验证自动封禁过期时间
	if cfg.AutoBlock && cfg.AutoBlockExpiry != "" {
		if _, err := time.ParseDuration(cfg.AutoBlockExpiry); err != nil {
			result.AddError("rate_limit.auto_block_expiry",
				fmt.Sprintf("Invalid duration format: %v", err), cfg.AutoBlockExpiry)
		}
	}

	// Validate rate limit rules / 验证速率限制规则
	for i, rule := range cfg.Rules {
		fieldPrefix := fmt.Sprintf("rate_limit.rules[%d]", i)

		// Validate IP/CIDR / 验证 IP/CIDR
		if rule.IP != "" {
			if _, _, err := net.ParseCIDR(rule.IP); err != nil {
				if ip := net.ParseIP(rule.IP); ip == nil {
					result.AddError(fmt.Sprintf("%s.ip", fieldPrefix),
						fmt.Sprintf("Invalid IP or CIDR format: %s", rule.IP), rule.IP)
				}
			}
		}

		// Validate rate / 验证速率
		if rule.Rate > v.MaxRate {
			result.AddError(fmt.Sprintf("%s.rate", fieldPrefix),
				fmt.Sprintf("Rate exceeds maximum allowed value (%d)", v.MaxRate), rule.Rate)
		}

		// Validate burst / 验证突发量
		if rule.Burst > v.MaxBurst {
			result.AddError(fmt.Sprintf("%s.burst", fieldPrefix),
				fmt.Sprintf("Burst exceeds maximum allowed value (%d)", v.MaxBurst), rule.Burst)
		}

		// Validate burst >= rate / 验证突发量 >= 速率
		if rule.Burst > 0 && rule.Rate > 0 && rule.Burst < rule.Rate {
			result.AddWarning(fmt.Sprintf("%s.burst", fieldPrefix),
				"Burst should be >= rate for proper token bucket behavior", rule.Burst)
		}
	}
}

// ValidateConfig validates a configuration from raw YAML data.
// ValidateConfig 从原始 YAML 数据验证配置。
func ValidateConfig(configData []byte) (*ValidationResult, error) {
	validator := NewConfigValidator()

	// First validate syntax / 首先验证语法
	syntaxResult := validator.ValidateSyntax(configData)
	if !syntaxResult.Valid {
		return syntaxResult, nil
	}

	// Parse configuration / 解析配置
	var cfg GlobalConfig
	if _, err := toml.Decode(string(configData), &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// Validate parsed config / 验证解析后的配置
	return validator.Validate(&cfg), nil
}

// ValidateConfigStruct validates a GlobalConfig struct directly.
// ValidateConfigStruct 直接验证 GlobalConfig 结构体。
func ValidateConfigStruct(cfg *GlobalConfig) *ValidationResult {
	validator := NewConfigValidator()
	return validator.Validate(cfg)
}
