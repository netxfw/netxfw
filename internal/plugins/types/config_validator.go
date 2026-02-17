package types

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
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
	if err := yaml.Unmarshal(configData, &rawConfig); err != nil {
		result.AddError("config", fmt.Sprintf("YAML syntax error: %v", err), nil)
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
	// Validate ICMP rate / 验证 ICMP 速率
	if cfg.ICMPRate > v.MaxRate {
		result.AddError("base.icmp_rate",
			fmt.Sprintf("ICMP rate exceeds maximum allowed value (%d)", v.MaxRate), cfg.ICMPRate)
	}

	// Validate ICMP burst / 验证 ICMP 突发量
	if cfg.ICMPBurst > v.MaxBurst {
		result.AddError("base.icmp_burst",
			fmt.Sprintf("ICMP burst exceeds maximum allowed value (%d)", v.MaxBurst), cfg.ICMPBurst)
	}

	// Validate ICMP burst >= rate / 验证 ICMP 突发量 >= 速率
	if cfg.ICMPBurst > 0 && cfg.ICMPRate > 0 && cfg.ICMPBurst < cfg.ICMPRate {
		result.AddWarning("base.icmp_burst",
			"ICMP burst should be >= rate for proper token bucket behavior", cfg.ICMPBurst)
	}

	// Validate cleanup interval / 验证清理间隔
	if cfg.CleanupInterval != "" {
		duration, err := time.ParseDuration(cfg.CleanupInterval)
		if err != nil {
			result.AddError("base.cleanup_interval",
				fmt.Sprintf("Invalid duration format: %v", err), cfg.CleanupInterval)
		} else {
			if duration < v.MinCleanupInterval {
				result.AddWarning("base.cleanup_interval",
					fmt.Sprintf("Cleanup interval is very short (min recommended: %v)", v.MinCleanupInterval), cfg.CleanupInterval)
			}
			if duration > v.MaxCleanupInterval {
				result.AddWarning("base.cleanup_interval",
					fmt.Sprintf("Cleanup interval is very long (max recommended: %v)", v.MaxCleanupInterval), cfg.CleanupInterval)
			}
		}
	}

	// Validate pprof port / 验证 pprof 端口
	if cfg.EnablePprof && (cfg.PprofPort < 1 || cfg.PprofPort > v.MaxPort) {
		result.AddError("base.pprof_port",
			fmt.Sprintf("Port must be between 1 and %d", v.MaxPort), cfg.PprofPort)
	}

	// Validate whitelist CIDRs / 验证白名单 CIDR
	for i, cidr := range cfg.Whitelist {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			if ip := net.ParseIP(cidr); ip == nil {
				result.AddError(fmt.Sprintf("base.whitelist[%d]", i),
					fmt.Sprintf("Invalid IP or CIDR format: %s", cidr), cidr)
			}
		}
	}

	// Validate lock list merge threshold / 验证锁定列表合并阈值
	if cfg.LockListMergeThreshold < 0 {
		result.AddError("base.lock_list_merge_threshold",
			"Merge threshold cannot be negative", cfg.LockListMergeThreshold)
	}

	// Validate IPv4 mask range / 验证 IPv4 掩码范围
	if cfg.LockListV4Mask < 0 || cfg.LockListV4Mask > 32 {
		result.AddError("base.lock_list_v4_mask",
			"IPv4 mask must be between 0 and 32", cfg.LockListV4Mask)
	}

	// Validate IPv6 mask range / 验证 IPv6 掩码范围
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
		if rule.Port < 0 || int(rule.Port) > v.MaxPort {
			result.AddError(fmt.Sprintf("%s.port", fieldPrefix),
				fmt.Sprintf("Port must be between 0 and %d", v.MaxPort), rule.Port)
		}

		// Validate action / 验证动作
		if rule.Action != 0 && rule.Action != 1 && rule.Action != 2 {
			result.AddError(fmt.Sprintf("%s.action", fieldPrefix),
				"Action must be 0 (default), 1 (allow), or 2 (deny)", rule.Action)
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

// validateLogEngineConfig validates log engine configuration.
// validateLogEngineConfig 验证日志引擎配置。
func (v *ConfigValidator) validateLogEngineConfig(cfg *LogEngineConfig, result *ValidationResult) {
	if !cfg.Enabled {
		return
	}

	// Validate workers / 验证工作线程数
	if cfg.Workers < 1 {
		result.AddError("log_engine.workers",
			"At least 1 worker is required", cfg.Workers)
	} else if cfg.Workers > 100 {
		result.AddWarning("log_engine.workers",
			"Very high worker count may impact performance", cfg.Workers)
	}

	// Validate max window / 验证最大窗口
	if cfg.MaxWindow < 0 {
		result.AddError("log_engine.max_window",
			"Max window cannot be negative", cfg.MaxWindow)
	}

	// Validate rules / 验证规则
	for i, rule := range cfg.Rules {
		fieldPrefix := fmt.Sprintf("log_engine.rules[%d]", i)

		// Validate ID / 验证 ID
		if rule.ID == "" {
			result.AddError(fmt.Sprintf("%s.id", fieldPrefix),
				"Rule ID is required", nil)
		}

		// Validate path / 验证路径
		if rule.Path == "" {
			result.AddError(fmt.Sprintf("%s.path", fieldPrefix),
				"Log path is required", nil)
		}

		// Validate action / 验证动作
		if rule.Action != "" && rule.Action != "log" && rule.Action != "block" {
			result.AddError(fmt.Sprintf("%s.action", fieldPrefix),
				"Action must be 'log' or 'block'", rule.Action)
		}

		// Validate TTL / 验证 TTL
		if rule.TTL != "" {
			if _, err := time.ParseDuration(rule.TTL); err != nil {
				result.AddError(fmt.Sprintf("%s.ttl", fieldPrefix),
					fmt.Sprintf("Invalid duration format: %v", err), rule.TTL)
			}
		}

		// Validate regex / 验证正则表达式
		if rule.Regex != "" {
			if _, err := regexp.Compile(rule.Regex); err != nil {
				result.AddError(fmt.Sprintf("%s.regex", fieldPrefix),
					fmt.Sprintf("Invalid regex: %v", err), rule.Regex)
			}
		}

		// Validate threshold / 验证阈值
		if rule.Threshold < 0 {
			result.AddError(fmt.Sprintf("%s.threshold", fieldPrefix),
				"Threshold cannot be negative", rule.Threshold)
		}

		// Validate interval / 验证间隔
		if rule.Interval < 0 {
			result.AddError(fmt.Sprintf("%s.interval", fieldPrefix),
				"Interval cannot be negative", rule.Interval)
		}

		// Validate tail position / 验证读取位置
		if rule.TailPosition != "" {
			validPositions := []string{"start", "end", "offset"}
			valid := false
			for _, pos := range validPositions {
				if rule.TailPosition == pos {
					valid = true
					break
				}
			}
			if !valid {
				result.AddError(fmt.Sprintf("%s.tail_position", fieldPrefix),
					fmt.Sprintf("Tail position must be one of: %v", validPositions), rule.TailPosition)
			}
		}
	}
}

// validateCapacityConfig validates capacity configuration.
// validateCapacityConfig 验证容量配置。
func (v *ConfigValidator) validateCapacityConfig(cfg *CapacityConfig, result *ValidationResult) {
	// Validate lock list capacity / 验证锁定列表容量
	if cfg.LockList < 0 {
		result.AddError("capacity.lock_list",
			"Lock list capacity cannot be negative", cfg.LockList)
	} else if cfg.LockList > v.MaxMapCapacity {
		result.AddWarning("capacity.lock_list",
			fmt.Sprintf("Lock list capacity is very high (max recommended: %d)", v.MaxMapCapacity), cfg.LockList)
	}

	// Validate dynamic lock list capacity / 验证动态锁定列表容量
	if cfg.DynLockList < 0 {
		result.AddError("capacity.dyn_lock_list",
			"Dynamic lock list capacity cannot be negative", cfg.DynLockList)
	} else if cfg.DynLockList > v.MaxMapCapacity {
		result.AddWarning("capacity.dyn_lock_list",
			fmt.Sprintf("Dynamic lock list capacity is very high (max recommended: %d)", v.MaxMapCapacity), cfg.DynLockList)
	}

	// Validate whitelist capacity / 验证白名单容量
	if cfg.Whitelist < 0 {
		result.AddError("capacity.whitelist",
			"Whitelist capacity cannot be negative", cfg.Whitelist)
	}

	// Validate IP-Port rules capacity / 验证 IP-端口规则容量
	if cfg.IPPortRules < 0 {
		result.AddError("capacity.ip_port_rules",
			"IP-Port rules capacity cannot be negative", cfg.IPPortRules)
	}

	// Validate allowed ports capacity / 验证允许端口容量
	if cfg.AllowedPorts < 0 {
		result.AddError("capacity.allowed_ports",
			"Allowed ports capacity cannot be negative", cfg.AllowedPorts)
	}

	// Validate drop reason stats capacity / 验证丢弃原因统计容量
	if cfg.DropReasonStats < 0 {
		result.AddError("capacity.drop_reason_stats",
			"Drop reason stats capacity cannot be negative", cfg.DropReasonStats)
	}

	// Validate pass reason stats capacity / 验证通过原因统计容量
	if cfg.PassReasonStats < 0 {
		result.AddError("capacity.pass_reason_stats",
			"Pass reason stats capacity cannot be negative", cfg.PassReasonStats)
	}
}

// validateLoggingConfig validates logging configuration.
// validateLoggingConfig 验证日志配置。
func (v *ConfigValidator) validateLoggingConfig(cfg *LoggingConfig, result *ValidationResult) {
	if !cfg.Enabled {
		return
	}

	// Validate log level / 验证日志级别
	if cfg.Level != "" {
		validLevels := []string{"debug", "info", "warn", "error"}
		valid := false
		for _, level := range validLevels {
			if strings.ToLower(cfg.Level) == level {
				valid = true
				break
			}
		}
		if !valid {
			result.AddError("logging.level",
				fmt.Sprintf("Log level must be one of: %v", validLevels), cfg.Level)
		}
	}

	// Validate path / 验证路径
	if cfg.Path == "" {
		result.AddError("logging.path",
			"Log path is required when logging is enabled", nil)
	}

	// Validate max size / 验证最大大小
	if cfg.MaxSize < 0 {
		result.AddError("logging.max_size",
			"Max size cannot be negative", cfg.MaxSize)
	} else if cfg.MaxSize > 1000 {
		result.AddWarning("logging.max_size",
			"Very large log file size may cause disk space issues", cfg.MaxSize)
	}

	// Validate max backups / 验证最大备份数
	if cfg.MaxBackups < 0 {
		result.AddError("logging.max_backups",
			"Max backups cannot be negative", cfg.MaxBackups)
	}

	// Validate max age / 验证最大保留天数
	if cfg.MaxAge < 0 {
		result.AddError("logging.max_age",
			"Max age cannot be negative", cfg.MaxAge)
	}
}

// detectConflicts detects conflicts between different configuration sections.
// detectConflicts 检测不同配置部分之间的冲突。
func (v *ConfigValidator) detectConflicts(cfg *GlobalConfig, result *ValidationResult) {
	// Check for overlapping IPs between whitelist and rate limit rules
	// 检查白名单和速率限制规则之间的 IP 重叠
	for _, wlCIDR := range cfg.Base.Whitelist {
		_, wlNet, err := net.ParseCIDR(wlCIDR)
		if err != nil {
			if ip := net.ParseIP(wlCIDR); ip != nil {
				wlNet = &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
				if ip.To4() == nil {
					wlNet = &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
				}
			} else {
				continue
			}
		}

		for i, rlRule := range cfg.RateLimit.Rules {
			_, rlNet, err := net.ParseCIDR(rlRule.IP)
			if err != nil {
				if ip := net.ParseIP(rlRule.IP); ip != nil {
					rlNet = &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
					if ip.To4() == nil {
						rlNet = &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
					}
				} else {
					continue
				}
			}

			if v.networksOverlap(wlNet, rlNet) {
				result.AddWarning(fmt.Sprintf("rate_limit.rules[%d].ip", i),
					fmt.Sprintf("IP/CIDR overlaps with whitelist entry '%s' - rate limiting whitelisted IPs may cause unexpected behavior", wlCIDR), rlRule.IP)
			}
		}
	}

	// Check for duplicate ports in allowed_ports
	// 检查 allowed_ports 中的重复端口
	portSet := make(map[uint16]int)
	for i, port := range cfg.Port.AllowedPorts {
		if existingIdx, exists := portSet[port]; exists {
			result.AddWarning(fmt.Sprintf("port.allowed_ports[%d]", i),
				fmt.Sprintf("Duplicate port %d already defined at index %d", port, existingIdx), port)
		}
		portSet[port] = i
	}

	// Check for conflicting IP-Port rules
	// 检查冲突的 IP-端口规则
	type ruleKey struct {
		ip   string
		port uint16
	}
	ruleSet := make(map[ruleKey]int)
	for i, rule := range cfg.Port.IPPortRules {
		key := ruleKey{ip: rule.IP, port: rule.Port}
		if existingIdx, exists := ruleSet[key]; exists {
			result.AddWarning(fmt.Sprintf("port.ip_port_rules[%d]", i),
				fmt.Sprintf("Duplicate IP+Port rule already defined at index %d", existingIdx), rule)
		}
		ruleSet[key] = i
	}

	// Check for conflicting rate limit rules (same IP)
	// 检查冲突的速率限制规则（相同 IP）
	rlSet := make(map[string]int)
	for i, rule := range cfg.RateLimit.Rules {
		if existingIdx, exists := rlSet[rule.IP]; exists {
			result.AddWarning(fmt.Sprintf("rate_limit.rules[%d]", i),
				fmt.Sprintf("Duplicate rate limit rule for IP '%s' already defined at index %d", rule.IP, existingIdx), rule.IP)
		}
		rlSet[rule.IP] = i
	}

	// Check if web and metrics use the same port
	// 检查 Web 和指标是否使用相同端口
	if cfg.Web.Enabled && cfg.Metrics.ServerEnabled && cfg.Web.Port == cfg.Metrics.Port {
		result.AddError("web.port",
			fmt.Sprintf("Web and metrics server cannot use the same port (%d)", cfg.Web.Port), cfg.Web.Port)
	}

	// Check if web and pprof use the same port
	// 检查 Web 和 pprof 是否使用相同端口
	if cfg.Web.Enabled && cfg.Base.EnablePprof && cfg.Web.Port == cfg.Base.PprofPort {
		result.AddWarning("base.pprof_port",
			fmt.Sprintf("Web and pprof server use the same port (%d) - this may cause conflicts", cfg.Web.Port), cfg.Base.PprofPort)
	}

	// Check for conflicting log engine rules (same path + ID)
	// 检查冲突的日志引擎规则（相同路径 + ID）
	logRuleSet := make(map[string]int)
	for i, rule := range cfg.LogEngine.Rules {
		key := rule.Path + ":" + rule.ID
		if existingIdx, exists := logRuleSet[key]; exists {
			result.AddWarning(fmt.Sprintf("log_engine.rules[%d]", i),
				fmt.Sprintf("Duplicate log engine rule (path+id) already defined at index %d", existingIdx), rule.ID)
		}
		logRuleSet[key] = i
	}
}

// networksOverlap checks if two networks overlap.
// networksOverlap 检查两个网络是否重叠。
func (v *ConfigValidator) networksOverlap(n1, n2 *net.IPNet) bool {
	return n1.Contains(n2.IP) || n2.Contains(n1.IP)
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
	if err := yaml.Unmarshal(configData, &cfg); err != nil {
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
