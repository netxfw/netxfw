package types

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/netxfw/netxfw/internal/utils/logger"
)

// validateLogEngineConfig validates log engine configuration.
// validateLogEngineConfig 验证日志引擎配置。
func (v *ConfigValidator) validateLogEngineConfig(cfg *LogEngineConfig, result *ValidationResult) {
	if !cfg.Enabled {
		return
	}

	v.validateLogEngineWorkers(cfg, result)
	v.validateLogEngineMaxWindow(cfg, result)
	v.validateLogEngineRules(cfg, result)
}

// validateLogEngineWorkers validates log engine worker count.
// validateLogEngineWorkers 验证日志引擎工作线程数。
func (v *ConfigValidator) validateLogEngineWorkers(cfg *LogEngineConfig, result *ValidationResult) {
	if cfg.Workers < 1 {
		result.AddError("log_engine.workers",
			"At least 1 worker is required", cfg.Workers)
	} else if cfg.Workers > 100 {
		result.AddWarning("log_engine.workers",
			"Very high worker count may impact performance", cfg.Workers)
	}
}

// validateLogEngineMaxWindow validates log engine max window.
// validateLogEngineMaxWindow 验证日志引擎最大窗口。
func (v *ConfigValidator) validateLogEngineMaxWindow(cfg *LogEngineConfig, result *ValidationResult) {
	if cfg.MaxWindow < 0 {
		result.AddError("log_engine.max_window",
			"Max window cannot be negative", cfg.MaxWindow)
	}
}

// validateLogEngineRules validates log engine rules.
// validateLogEngineRules 验证日志引擎规则。
func (v *ConfigValidator) validateLogEngineRules(cfg *LogEngineConfig, result *ValidationResult) {
	for i := range cfg.Rules {
		rule := &cfg.Rules[i]
		fieldPrefix := fmt.Sprintf("log_engine.rules[%d]", i)
		v.validateLogEngineRule(rule, fieldPrefix, result)
	}
}

// validateLogEngineRule validates a single log engine rule.
// validateLogEngineRule 验证单个日志引擎规则。
func (v *ConfigValidator) validateLogEngineRule(rule *LogEngineRule, fieldPrefix string, result *ValidationResult) {
	if rule.ID == "" {
		result.AddError(fmt.Sprintf("%s.id", fieldPrefix),
			"Rule ID is required", nil)
	}

	if rule.Path == "" {
		result.AddError(fmt.Sprintf("%s.path", fieldPrefix),
			"Log path is required", nil)
	}

	if rule.Action != "" && rule.Action != "log" && rule.Action != "block" {
		result.AddError(fmt.Sprintf("%s.action", fieldPrefix),
			"Action must be 'log' or 'block'", rule.Action)
	}

	if rule.TTL != "" {
		if _, err := time.ParseDuration(rule.TTL); err != nil {
			result.AddError(fmt.Sprintf("%s.ttl", fieldPrefix),
				fmt.Sprintf("Invalid duration format: %v", err), rule.TTL)
		}
	}

	if rule.Regex != "" {
		if _, err := regexp.Compile(rule.Regex); err != nil {
			result.AddError(fmt.Sprintf("%s.regex", fieldPrefix),
				fmt.Sprintf("Invalid regex: %v", err), rule.Regex)
		}
	}

	if rule.Threshold < 0 {
		result.AddError(fmt.Sprintf("%s.threshold", fieldPrefix),
			"Threshold cannot be negative", rule.Threshold)
	}

	if rule.Interval < 0 {
		result.AddError(fmt.Sprintf("%s.interval", fieldPrefix),
			"Interval cannot be negative", rule.Interval)
	}

	v.validateTailPosition(rule, fieldPrefix, result)
}

// validateTailPosition validates tail position configuration.
// validateTailPosition 验证读取位置配置。
func (v *ConfigValidator) validateTailPosition(rule *LogEngineRule, fieldPrefix string, result *ValidationResult) {
	if rule.TailPosition == "" {
		return
	}

	validPositions := []string{"start", "end", "offset"}
	for _, pos := range validPositions {
		if rule.TailPosition == pos {
			return
		}
	}
	result.AddError(fmt.Sprintf("%s.tail_position", fieldPrefix),
		fmt.Sprintf("Tail position must be one of: %v", validPositions), rule.TailPosition)
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
func (v *ConfigValidator) validateLoggingConfig(cfg *logger.LoggingConfig, result *ValidationResult) {
	if !cfg.Enabled {
		return
	}

	// Validate log level / 验证日志级别
	if cfg.Level != "" {
		validLevels := []string{"debug", "info", "warn", "error"}
		valid := false
		for _, level := range validLevels {
			if strings.EqualFold(cfg.Level, level) {
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
