package config

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

// ValidationError represents a single validation error.
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
	Value   any    `json:"value"`
}

// ValidationWarning represents a potential issue that's not critical.
type ValidationWarning struct {
	Field   string `json:"field"`
	Message string `json:"message"`
	Value   any    `json:"value"`
}

// ValidationResult contains all validation errors and warnings.
type ValidationResult struct {
	Valid    bool                `json:"valid"`
	Errors   []ValidationError   `json:"errors"`
	Warnings []ValidationWarning `json:"warnings"`
}

func (r *ValidationResult) AddError(field, message string, value any) {
	r.Errors = append(r.Errors, ValidationError{
		Field:   field,
		Message: message,
		Value:   value,
	})
	r.Valid = false
}

func (r *ValidationResult) AddWarning(field, message string, value any) {
	r.Warnings = append(r.Warnings, ValidationWarning{
		Field:   field,
		Message: message,
		Value:   value,
	})
}

func (r *ValidationResult) String() string {
	if r.Valid && len(r.Warnings) == 0 {
		return "Configuration validation passed with no issues."
	}

	var sb strings.Builder
	sb.WriteString("Configuration Validation Report\n")
	sb.WriteString("===============================\n\n")

	if !r.Valid {
		sb.WriteString(fmt.Sprintf("Status: FAILED (%d errors, %d warnings)\n\n", len(r.Errors), len(r.Warnings)))
		sb.WriteString("Errors:\n")
		for i, err := range r.Errors {
			sb.WriteString(fmt.Sprintf("  %d. [%s] %s", i+1, err.Field, err.Message))
			if err.Value != nil {
				sb.WriteString(fmt.Sprintf(" (value: %v)", err.Value))
			}
			sb.WriteString("\n")
		}
	} else {
		sb.WriteString(fmt.Sprintf("Status: PASSED (%d warnings)\n\n", len(r.Warnings)))
	}

	if len(r.Warnings) > 0 {
		sb.WriteString("Warnings:\n")
		for i, warn := range r.Warnings {
			sb.WriteString(fmt.Sprintf("  %d. [%s] %s", i+1, warn.Field, warn.Message))
			if warn.Value != nil {
				sb.WriteString(fmt.Sprintf(" (value: %v)", warn.Value))
			}
			sb.WriteString("\n")
		}
	}

	return sb.String()
}

// ConfigValidator provides configuration validation functionality.
type ConfigValidator struct {
	MaxPort            int
	MaxRate            uint64
	MaxBurst           uint64
	MaxMapCapacity     int
	MaxCleanupInterval time.Duration
	MinCleanupInterval time.Duration
}

func NewConfigValidator() *ConfigValidator {
	return &ConfigValidator{
		MaxPort:            65535,
		MaxRate:            10000000,
		MaxBurst:           50000000,
		MaxMapCapacity:     10000000,
		MaxCleanupInterval: 24 * time.Hour,
		MinCleanupInterval: 10 * time.Second,
	}
}

func (v *ConfigValidator) ValidateSyntax(configData []byte) *ValidationResult {
	result := &ValidationResult{Valid: true, Errors: []ValidationError{}, Warnings: []ValidationWarning{}}

	var rawConfig map[string]any
	if _, err := toml.Decode(string(configData), &rawConfig); err != nil {
		result.AddError("config", fmt.Sprintf("TOML syntax error: %v", err), nil)
		return result
	}

	return result
}

func (v *ConfigValidator) Validate(cfg *Config) *ValidationResult {
	result := &ValidationResult{Valid: true, Errors: []ValidationError{}, Warnings: []ValidationWarning{}}

	v.validateBaseConfig(&cfg.Base, result)
	v.validateWebConfig(&cfg.Web, result)
	v.validateMetricsConfig(&cfg.Metrics, result)
	v.validatePortConfig(&cfg.Port, result)
	v.validateConntrackConfig(&cfg.Conntrack, result)
	v.validateRateLimitConfig(&cfg.RateLimit, result)
	v.validateLogEngineConfig(&cfg.LogEngine, result)
	v.validateCapacityConfig(&cfg.Capacity, result)
	v.validateLoggingConfig(&cfg.Logging, result)
	v.validateBPFPluginConfig(&cfg.BPFPlugin, result)
	v.detectConflicts(cfg, result)

	return result
}

func (v *ConfigValidator) validateBaseConfig(cfg *BaseConfig, result *ValidationResult) {
	v.validateICMPConfig(cfg, result)
	v.validateCleanupInterval(cfg, result)
	v.validatePprofConfig(cfg, result)
	v.validateWhitelistCIDRs(cfg, result)
	v.validateLockListMasks(cfg, result)
}

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

func (v *ConfigValidator) validatePprofConfig(cfg *BaseConfig, result *ValidationResult) {
	if cfg.EnablePprof && (cfg.PprofPort < 1 || cfg.PprofPort > v.MaxPort) {
		result.AddError("base.pprof_port",
			fmt.Sprintf("Port must be between 1 and %d", v.MaxPort), cfg.PprofPort)
	}
}

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

func (v *ConfigValidator) validateWebConfig(cfg *WebConfig, result *ValidationResult) {
	if !cfg.Enabled {
		return
	}
	if cfg.Port < 1 || cfg.Port > v.MaxPort {
		result.AddError("web.port",
			fmt.Sprintf("Port must be between 1 and %d", v.MaxPort), cfg.Port)
	}
	if cfg.Token == "" {
		result.AddWarning("web.token",
			"Web interface is enabled without authentication token - not recommended for production", nil)
	}
}

func (v *ConfigValidator) validateMetricsConfig(cfg *MetricsConfig, result *ValidationResult) {
	if !cfg.Enabled && !cfg.ServerEnabled {
		return
	}
	if cfg.Port < 1 || cfg.Port > v.MaxPort {
		result.AddError("metrics.port",
			fmt.Sprintf("Port must be between 1 and %d", v.MaxPort), cfg.Port)
	}
	if cfg.PushEnabled && cfg.PushInterval != "" {
		if _, err := time.ParseDuration(cfg.PushInterval); err != nil {
			result.AddError("metrics.push_interval",
				fmt.Sprintf("Invalid duration format: %v", err), cfg.PushInterval)
		}
	}
	if cfg.PushEnabled && cfg.PushGatewayAddr == "" {
		result.AddError("metrics.push_gateway_addr",
			"Push gateway address is required when push is enabled", nil)
	}
}

func (v *ConfigValidator) validatePortConfig(cfg *PortConfig, result *ValidationResult) {
	for i, port := range cfg.AllowedPorts {
		if port == 0 {
			result.AddError(fmt.Sprintf("port.allowed_ports[%d]", i), "Port 0 is not allowed in allowed_ports", port)
		}
	}

	for i, rule := range cfg.IPPortRules {
		if rule.Port == 0 {
			result.AddError(fmt.Sprintf("port.ip_port_rules[%d].port", i), "Port 0 is not allowed in IP-port rules", rule.Port)
		}
		if err := ValidateIPPortRuleAction(rule.Action); err != nil {
			result.AddError(fmt.Sprintf("port.ip_port_rules[%d].action", i), err.Error(), rule.Action)
		}
		if err := ValidateCIDROrIPForConfig(rule.IP); err != nil {
			result.AddError(fmt.Sprintf("port.ip_port_rules[%d].ip", i),
				fmt.Sprintf("Invalid IP or CIDR format: %s", rule.IP), rule.IP)
		}
	}
}

func (v *ConfigValidator) validateConntrackConfig(cfg *ConntrackConfig, result *ValidationResult) {
	if !cfg.Enabled {
		return
	}
	if cfg.MaxEntries < 0 {
		result.AddError("conntrack.max_entries", "Max entries cannot be negative", cfg.MaxEntries)
	}
	if cfg.TCPTimeout != "" {
		if _, err := time.ParseDuration(cfg.TCPTimeout); err != nil {
			result.AddError("conntrack.tcp_timeout",
				fmt.Sprintf("Invalid duration format: %v", err), cfg.TCPTimeout)
		}
	}
	if cfg.UDPTimeout != "" {
		if _, err := time.ParseDuration(cfg.UDPTimeout); err != nil {
			result.AddError("conntrack.udp_timeout",
				fmt.Sprintf("Invalid duration format: %v", err), cfg.UDPTimeout)
		}
	}
}

func (v *ConfigValidator) validateRateLimitConfig(cfg *RateLimitConfig, result *ValidationResult) {
	if !cfg.Enabled {
		return
	}
	if cfg.AutoBlockExpiry != "" {
		if _, err := time.ParseDuration(cfg.AutoBlockExpiry); err != nil {
			result.AddError("rate_limit.auto_block_expiry",
				fmt.Sprintf("Invalid duration format: %v", err), cfg.AutoBlockExpiry)
		}
	}
	for i, rule := range cfg.Rules {
		if _, _, err := net.ParseCIDR(rule.IP); err != nil {
			if ip := net.ParseIP(rule.IP); ip == nil {
				result.AddError(fmt.Sprintf("rate_limit.rules[%d].ip", i),
					fmt.Sprintf("Invalid IP or CIDR format: %s", rule.IP), rule.IP)
			}
		}
		if rule.Rate == 0 {
			result.AddError(fmt.Sprintf("rate_limit.rules[%d].rate", i), "Rate must be greater than 0", rule.Rate)
		} else if rule.Rate > v.MaxRate {
			result.AddError(fmt.Sprintf("rate_limit.rules[%d].rate", i),
				fmt.Sprintf("Rate exceeds maximum allowed value (%d)", v.MaxRate), rule.Rate)
		}
		if rule.Burst == 0 {
			result.AddError(fmt.Sprintf("rate_limit.rules[%d].burst", i), "Burst must be greater than 0", rule.Burst)
		} else if rule.Burst > v.MaxBurst {
			result.AddError(fmt.Sprintf("rate_limit.rules[%d].burst", i),
				fmt.Sprintf("Burst exceeds maximum allowed value (%d)", v.MaxBurst), rule.Burst)
		}
	}
}

func ValidateConfig(configData []byte) (*ValidationResult, error) {
	validator := NewConfigValidator()

	syntaxResult := validator.ValidateSyntax(configData)
	if !syntaxResult.Valid {
		return syntaxResult, nil
	}

	cfg := DefaultConfig()
	if _, err := toml.Decode(string(configData), &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	return validator.Validate(&cfg), nil
}

func ValidateConfigStruct(cfg *Config) *ValidationResult {
	validator := NewConfigValidator()
	return validator.Validate(cfg)
}
