package config

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

func (v *ConfigValidator) validateLogEngineConfig(cfg *LogEngineConfig, result *ValidationResult) {
	if !cfg.Enabled {
		return
	}

	v.validateLogEngineWorkers(cfg, result)
	v.validateLogEngineMaxWindow(cfg, result)
	v.validateLogEngineRules(cfg, result)
}

func (v *ConfigValidator) validateLogEngineWorkers(cfg *LogEngineConfig, result *ValidationResult) {
	if cfg.Workers < 1 {
		result.AddError("log_engine.workers", "At least 1 worker is required", cfg.Workers)
	} else if cfg.Workers > 100 {
		result.AddWarning("log_engine.workers", "Very high worker count may impact performance", cfg.Workers)
	}
}

func (v *ConfigValidator) validateLogEngineMaxWindow(cfg *LogEngineConfig, result *ValidationResult) {
	if cfg.MaxWindow < 0 {
		result.AddError("log_engine.max_window", "Max window cannot be negative", cfg.MaxWindow)
	}
}

func (v *ConfigValidator) validateLogEngineRules(cfg *LogEngineConfig, result *ValidationResult) {
	for i := range cfg.Rules {
		rule := &cfg.Rules[i]
		fieldPrefix := fmt.Sprintf("log_engine.rules[%d]", i)
		v.validateLogEngineRule(rule, fieldPrefix, result)
	}
}

func (v *ConfigValidator) validateLogEngineRule(rule *LogEngineRule, fieldPrefix string, result *ValidationResult) {
	if rule.ID == "" {
		result.AddError(fmt.Sprintf("%s.id", fieldPrefix), "Rule ID is required", nil)
	}
	if rule.Path == "" {
		result.AddError(fmt.Sprintf("%s.path", fieldPrefix), "Log path is required", nil)
	}
	if rule.Action != "" && rule.Action != "log" && rule.Action != "block" {
		result.AddError(fmt.Sprintf("%s.action", fieldPrefix), "Action must be 'log' or 'block'", rule.Action)
	}
	if rule.TTL != "" {
		if _, err := time.ParseDuration(rule.TTL); err != nil {
			result.AddError(fmt.Sprintf("%s.ttl", fieldPrefix), fmt.Sprintf("Invalid duration format: %v", err), rule.TTL)
		}
	}
	if rule.Regex != "" {
		if _, err := regexp.Compile(rule.Regex); err != nil {
			result.AddError(fmt.Sprintf("%s.regex", fieldPrefix), fmt.Sprintf("Invalid regex: %v", err), rule.Regex)
		}
	}
	if rule.Threshold < 0 {
		result.AddError(fmt.Sprintf("%s.threshold", fieldPrefix), "Threshold cannot be negative", rule.Threshold)
	}
	if rule.Interval < 0 {
		result.AddError(fmt.Sprintf("%s.interval", fieldPrefix), "Interval cannot be negative", rule.Interval)
	}

	v.validateTailPosition(rule, fieldPrefix, result)
}

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

func (v *ConfigValidator) validateCapacityConfig(cfg *CapacityConfig, result *ValidationResult) {
	if cfg.LockList < 0 {
		result.AddError("capacity.lock_list", "Lock list capacity cannot be negative", cfg.LockList)
	} else if cfg.LockList > v.MaxMapCapacity {
		result.AddWarning("capacity.lock_list",
			fmt.Sprintf("Lock list capacity is very high (max recommended: %d)", v.MaxMapCapacity), cfg.LockList)
	}
	if cfg.DynLockList < 0 {
		result.AddError("capacity.dyn_lock_list", "Dynamic lock list capacity cannot be negative", cfg.DynLockList)
	} else if cfg.DynLockList > v.MaxMapCapacity {
		result.AddWarning("capacity.dyn_lock_list",
			fmt.Sprintf("Dynamic lock list capacity is very high (max recommended: %d)", v.MaxMapCapacity), cfg.DynLockList)
	}
	if cfg.Whitelist < 0 {
		result.AddError("capacity.whitelist", "Whitelist capacity cannot be negative", cfg.Whitelist)
	}
	if cfg.IPPortRules < 0 {
		result.AddError("capacity.ip_port_rules", "IP-Port rules capacity cannot be negative", cfg.IPPortRules)
	}
	if cfg.AllowedPorts < 0 {
		result.AddError("capacity.allowed_ports", "Allowed ports capacity cannot be negative", cfg.AllowedPorts)
	}
	if cfg.DropReasonStats < 0 {
		result.AddError("capacity.drop_reason_stats", "Drop reason stats capacity cannot be negative", cfg.DropReasonStats)
	}
	if cfg.PassReasonStats < 0 {
		result.AddError("capacity.pass_reason_stats", "Pass reason stats capacity cannot be negative", cfg.PassReasonStats)
	}
}

func (v *ConfigValidator) validateLoggingConfig(cfg *LoggingConfig, result *ValidationResult) {
	if !cfg.Enabled {
		return
	}
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
			result.AddError("logging.level", fmt.Sprintf("Log level must be one of: %v", validLevels), cfg.Level)
		}
	}
	if cfg.Path == "" {
		result.AddError("logging.path", "Log path is required when logging is enabled", nil)
	}
	if cfg.MaxSize < 0 {
		result.AddError("logging.max_size", "Max size cannot be negative", cfg.MaxSize)
	} else if cfg.MaxSize > 1000 {
		result.AddWarning("logging.max_size", "Very large log file size may cause disk space issues", cfg.MaxSize)
	}
	if cfg.MaxBackups < 0 {
		result.AddError("logging.max_backups", "Max backups cannot be negative", cfg.MaxBackups)
	}
	if cfg.MaxAge < 0 {
		result.AddError("logging.max_age", "Max age cannot be negative", cfg.MaxAge)
	}
}
