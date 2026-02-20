package xdp

import (
	"fmt"

	"github.com/livp123/netxfw/internal/plugins/types"
)

// ConfigDiff represents the difference between two configurations.
// ConfigDiff 表示两个配置之间的差异。
type ConfigDiff struct {
	// Global config changes / 全局配置变更
	GlobalConfigChanges map[string]ConfigChange

	// Blacklist changes / 黑名单变更
	BlacklistAdded   []string
	BlacklistRemoved []string

	// Whitelist changes / 白名单变更
	WhitelistAdded   []string
	WhitelistRemoved []string

	// IP+Port rule changes / IP+端口规则变更
	IPPortAdded   []IPPortRuleChange
	IPPortRemoved []IPPortRuleChange

	// Rate limit rule changes / 速率限制规则变更
	RateLimitAdded   []RateLimitChange
	RateLimitRemoved []RateLimitChange
	RateLimitUpdated []RateLimitChange
}

// ConfigChange represents a single configuration change.
// ConfigChange 表示单个配置变更。
type ConfigChange struct {
	Field    string
	OldValue any
	NewValue any
}

// IPPortRuleChange represents an IP+Port rule change.
// IPPortRuleChange 表示 IP+端口规则变更。
type IPPortRuleChange struct {
	IP     string
	Port   uint16
	Action uint8
}

// RateLimitChange represents a rate limit rule change.
// RateLimitChange 表示速率限制规则变更。
type RateLimitChange struct {
	CIDR  string
	Rate  uint64
	Burst uint64
}

// IncrementalUpdater handles incremental configuration updates.
// IncrementalUpdater 处理增量配置更新。
type IncrementalUpdater struct {
	mgr *Manager
}

// NewIncrementalUpdater creates a new incremental updater.
// NewIncrementalUpdater 创建新的增量更新器。
func NewIncrementalUpdater(mgr *Manager) *IncrementalUpdater {
	return &IncrementalUpdater{mgr: mgr}
}

// ComputeDiff computes the difference between old and new configurations.
// ComputeDiff 计算旧配置和新配置之间的差异。
func (u *IncrementalUpdater) ComputeDiff(oldCfg, newCfg *types.GlobalConfig) (*ConfigDiff, error) {
	diff := &ConfigDiff{
		GlobalConfigChanges: make(map[string]ConfigChange),
	}

	// Compare global config fields / 比较全局配置字段
	u.compareGlobalConfig(oldCfg, newCfg, diff)

	// Compare blacklist / 比较黑名单
	if err := u.compareBlacklist(oldCfg, newCfg, diff); err != nil {
		return nil, fmt.Errorf("compare blacklist: %w", err)
	}

	// Compare whitelist / 比较白名单
	if err := u.compareWhitelist(oldCfg, newCfg, diff); err != nil {
		return nil, fmt.Errorf("compare whitelist: %w", err)
	}

	return diff, nil
}

// compareGlobalConfig compares global configuration fields.
// compareGlobalConfig 比较全局配置字段。
func (u *IncrementalUpdater) compareGlobalConfig(oldCfg, newCfg *types.GlobalConfig, diff *ConfigDiff) {
	// Base config fields / 基础配置字段
	if oldCfg.Base.DefaultDeny != newCfg.Base.DefaultDeny {
		diff.GlobalConfigChanges["default_deny"] = ConfigChange{
			Field:    "default_deny",
			OldValue: oldCfg.Base.DefaultDeny,
			NewValue: newCfg.Base.DefaultDeny,
		}
	}
	if oldCfg.Base.AllowReturnTraffic != newCfg.Base.AllowReturnTraffic {
		diff.GlobalConfigChanges["allow_return_traffic"] = ConfigChange{
			Field:    "allow_return_traffic",
			OldValue: oldCfg.Base.AllowReturnTraffic,
			NewValue: newCfg.Base.AllowReturnTraffic,
		}
	}
	if oldCfg.Base.AllowICMP != newCfg.Base.AllowICMP {
		diff.GlobalConfigChanges["allow_icmp"] = ConfigChange{
			Field:    "allow_icmp",
			OldValue: oldCfg.Base.AllowICMP,
			NewValue: newCfg.Base.AllowICMP,
		}
	}
	if oldCfg.Base.StrictProtocol != newCfg.Base.StrictProtocol {
		diff.GlobalConfigChanges["strict_protocol"] = ConfigChange{
			Field:    "strict_protocol",
			OldValue: oldCfg.Base.StrictProtocol,
			NewValue: newCfg.Base.StrictProtocol,
		}
	}
	if oldCfg.Base.StrictTCP != newCfg.Base.StrictTCP {
		diff.GlobalConfigChanges["strict_tcp"] = ConfigChange{
			Field:    "strict_tcp",
			OldValue: oldCfg.Base.StrictTCP,
			NewValue: newCfg.Base.StrictTCP,
		}
	}
	if oldCfg.Base.SYNLimit != newCfg.Base.SYNLimit {
		diff.GlobalConfigChanges["syn_limit"] = ConfigChange{
			Field:    "syn_limit",
			OldValue: oldCfg.Base.SYNLimit,
			NewValue: newCfg.Base.SYNLimit,
		}
	}
	if oldCfg.Base.BogonFilter != newCfg.Base.BogonFilter {
		diff.GlobalConfigChanges["bogon_filter"] = ConfigChange{
			Field:    "bogon_filter",
			OldValue: oldCfg.Base.BogonFilter,
			NewValue: newCfg.Base.BogonFilter,
		}
	}
	if oldCfg.Base.DropFragments != newCfg.Base.DropFragments {
		diff.GlobalConfigChanges["drop_fragments"] = ConfigChange{
			Field:    "drop_fragments",
			OldValue: oldCfg.Base.DropFragments,
			NewValue: newCfg.Base.DropFragments,
		}
	}
	if oldCfg.Base.EnableAFXDP != newCfg.Base.EnableAFXDP {
		diff.GlobalConfigChanges["enable_af_xdp"] = ConfigChange{
			Field:    "enable_af_xdp",
			OldValue: oldCfg.Base.EnableAFXDP,
			NewValue: newCfg.Base.EnableAFXDP,
		}
	}
	if oldCfg.Base.ICMPRate != newCfg.Base.ICMPRate || oldCfg.Base.ICMPBurst != newCfg.Base.ICMPBurst {
		diff.GlobalConfigChanges["icmp_rate_limit"] = ConfigChange{
			Field:    "icmp_rate_limit",
			OldValue: fmt.Sprintf("%d/%d", oldCfg.Base.ICMPRate, oldCfg.Base.ICMPBurst),
			NewValue: fmt.Sprintf("%d/%d", newCfg.Base.ICMPRate, newCfg.Base.ICMPBurst),
		}
	}

	// Conntrack config / 连接跟踪配置
	if oldCfg.Conntrack.Enabled != newCfg.Conntrack.Enabled {
		diff.GlobalConfigChanges["conntrack_enabled"] = ConfigChange{
			Field:    "conntrack_enabled",
			OldValue: oldCfg.Conntrack.Enabled,
			NewValue: newCfg.Conntrack.Enabled,
		}
	}

	// Rate limit config / 速率限制配置
	if oldCfg.RateLimit.Enabled != newCfg.RateLimit.Enabled {
		diff.GlobalConfigChanges["rate_limit_enabled"] = ConfigChange{
			Field:    "rate_limit_enabled",
			OldValue: oldCfg.RateLimit.Enabled,
			NewValue: newCfg.RateLimit.Enabled,
		}
	}
}

// compareBlacklist compares blacklist entries.
// compareBlacklist 比较黑名单条目。
func (u *IncrementalUpdater) compareBlacklist(oldCfg, newCfg *types.GlobalConfig, diff *ConfigDiff) error {
	// Check if map is available / 检查 Map 是否可用
	if u.mgr.staticBlacklist == nil {
		return nil // Skip comparison if map not available / 如果 Map 不可用则跳过比较
	}

	// Get current blacklist from map / 从 Map 获取当前黑名单
	currentBlacklist, _, err := ListBlockedIPs(u.mgr.staticBlacklist, false, 1000000, "")
	if err != nil {
		return err
	}

	// Create sets for comparison / 创建用于比较的集合
	oldSet := make(map[string]bool)
	for _, ip := range currentBlacklist {
		oldSet[ip.IP] = true
	}

	newSet := make(map[string]bool)
	// Add IPs from lock list file (would need to read from file)
	// For now, we compare with what's in the config whitelist only
	// 从锁定列表文件添加 IP（需要从文件读取）
	// 目前，我们只与配置白名单中的内容进行比较

	// Find added entries / 找到新增的条目
	for ip := range newSet {
		if !oldSet[ip] {
			diff.BlacklistAdded = append(diff.BlacklistAdded, ip)
		}
	}

	// Find removed entries / 找到移除的条目
	for ip := range oldSet {
		if !newSet[ip] {
			diff.BlacklistRemoved = append(diff.BlacklistRemoved, ip)
		}
	}

	return nil
}

// compareWhitelist compares whitelist entries.
// compareWhitelist 比较白名单条目。
func (u *IncrementalUpdater) compareWhitelist(oldCfg, newCfg *types.GlobalConfig, diff *ConfigDiff) error {
	// Check if map is available / 检查 Map 是否可用
	if u.mgr.whitelist == nil {
		return nil // Skip comparison if map not available / 如果 Map 不可用则跳过比较
	}

	// Get current whitelist from map / 从 Map 获取当前白名单
	currentWhitelist, _, err := ListWhitelistIPs(u.mgr.whitelist, 1000000, "")
	if err != nil {
		return err
	}

	// Create sets for comparison / 创建用于比较的集合
	oldSet := make(map[string]bool)
	for _, ip := range currentWhitelist {
		oldSet[ip] = true
	}

	newSet := make(map[string]bool)
	for _, ip := range newCfg.Base.Whitelist {
		newSet[ip] = true
	}

	// Find added entries / 找到新增的条目
	for ip := range newSet {
		if !oldSet[ip] {
			diff.WhitelistAdded = append(diff.WhitelistAdded, ip)
		}
	}

	// Find removed entries / 找到移除的条目
	for ip := range oldSet {
		if !newSet[ip] {
			diff.WhitelistRemoved = append(diff.WhitelistRemoved, ip)
		}
	}

	return nil
}

// ApplyDiff applies the configuration difference incrementally.
// ApplyDiff 增量应用配置差异。
func (u *IncrementalUpdater) ApplyDiff(diff *ConfigDiff) error {
	if diff == nil {
		return fmt.Errorf("diff is nil")
	}

	if !diff.HasChanges() {
		return nil
	}

	var errors []error
	var appliedCount int
	var failedCount int

	appliedCount, failedCount, errors = u.applyGlobalConfigChanges(diff, appliedCount, failedCount, errors)
	appliedCount, failedCount, errors = u.applyBlacklistChanges(diff, appliedCount, failedCount, errors)
	appliedCount, failedCount, errors = u.applyWhitelistChanges(diff, appliedCount, failedCount, errors)
	appliedCount, failedCount, errors = u.applyIPPortChanges(diff, appliedCount, failedCount, errors)

	if u.mgr.logger != nil {
		u.mgr.logger.Infof("📊 Incremental update: %d applied, %d failed", appliedCount, failedCount)
	}

	if len(errors) > 0 {
		return fmt.Errorf("incremental update completed with %d errors (applied: %d, failed: %d): %v", len(errors), appliedCount, failedCount, errors)
	}
	return nil
}

// applyGlobalConfigChanges applies global config changes.
// applyGlobalConfigChanges 应用全局配置变更。
func (u *IncrementalUpdater) applyGlobalConfigChanges(diff *ConfigDiff, applied, failed int, errors []error) (int, int, []error) {
	for field, change := range diff.GlobalConfigChanges {
		if err := u.applyGlobalConfigChange(field, change.NewValue); err != nil {
			errors = append(errors, fmt.Errorf("failed to apply %s: %w", field, err))
			failed++
		} else {
			applied++
		}
	}
	return applied, failed, errors
}

// applyBlacklistChanges applies blacklist changes.
// applyBlacklistChanges 应用黑名单变更。
func (u *IncrementalUpdater) applyBlacklistChanges(diff *ConfigDiff, applied, failed int, errors []error) (int, int, []error) {
	for _, ip := range diff.BlacklistAdded {
		if u.mgr.staticBlacklist == nil {
			errors = append(errors, fmt.Errorf("failed to add blacklist %s: staticBlacklist map is nil", ip))
			failed++
			continue
		}
		if err := u.mgr.BlockStatic(ip, ""); err != nil {
			errors = append(errors, fmt.Errorf("failed to add blacklist %s: %w", ip, err))
			failed++
		} else {
			applied++
		}
	}
	for _, ip := range diff.BlacklistRemoved {
		if u.mgr.staticBlacklist == nil {
			errors = append(errors, fmt.Errorf("failed to remove blacklist %s: staticBlacklist map is nil", ip))
			failed++
			continue
		}
		if err := UnlockIP(u.mgr.staticBlacklist, ip); err != nil {
			errors = append(errors, fmt.Errorf("failed to remove blacklist %s: %w", ip, err))
			failed++
		} else {
			applied++
		}
	}
	return applied, failed, errors
}

// applyWhitelistChanges applies whitelist changes.
// applyWhitelistChanges 应用白名单变更。
func (u *IncrementalUpdater) applyWhitelistChanges(diff *ConfigDiff, applied, failed int, errors []error) (int, int, []error) {
	for _, ip := range diff.WhitelistAdded {
		if u.mgr.whitelist == nil {
			errors = append(errors, fmt.Errorf("failed to add whitelist %s: whitelist map is nil", ip))
			failed++
			continue
		}
		if err := AllowIP(u.mgr.whitelist, ip, 0); err != nil {
			errors = append(errors, fmt.Errorf("failed to add whitelist %s: %w", ip, err))
			failed++
		} else {
			applied++
		}
	}
	for _, ip := range diff.WhitelistRemoved {
		if u.mgr.whitelist == nil {
			errors = append(errors, fmt.Errorf("failed to remove whitelist %s: whitelist map is nil", ip))
			failed++
			continue
		}
		if err := UnlockIP(u.mgr.whitelist, ip); err != nil {
			errors = append(errors, fmt.Errorf("failed to remove whitelist %s: %w", ip, err))
			failed++
		} else {
			applied++
		}
	}
	return applied, failed, errors
}

// applyIPPortChanges applies IP+Port rule changes.
// applyIPPortChanges 应用 IP+端口规则变更。
func (u *IncrementalUpdater) applyIPPortChanges(diff *ConfigDiff, applied, failed int, errors []error) (int, int, []error) {
	for _, rule := range diff.IPPortAdded {
		if u.mgr.ruleMap == nil {
			errors = append(errors, fmt.Errorf("failed to add IP+Port rule %s:%d: ruleMap is nil", rule.IP, rule.Port))
			failed++
			continue
		}
		if err := AddIPPortRuleToMapString(u.mgr.ruleMap, rule.IP, rule.Port, rule.Action); err != nil {
			errors = append(errors, fmt.Errorf("failed to add IP+Port rule %s:%d: %w", rule.IP, rule.Port, err))
			failed++
		} else {
			applied++
		}
	}
	for _, rule := range diff.IPPortRemoved {
		if u.mgr.ruleMap == nil {
			errors = append(errors, fmt.Errorf("failed to remove IP+Port rule %s:%d: ruleMap is nil", rule.IP, rule.Port))
			failed++
			continue
		}
		if err := RemoveIPPortRuleFromMapString(u.mgr.ruleMap, rule.IP, rule.Port); err != nil {
			errors = append(errors, fmt.Errorf("failed to remove IP+Port rule %s:%d: %w", rule.IP, rule.Port, err))
			failed++
		} else {
			applied++
		}
	}
	return applied, failed, errors
}

// applyGlobalConfigChange applies a single global config change.
// applyGlobalConfigChange 应用单个全局配置变更。
func (u *IncrementalUpdater) applyGlobalConfigChange(field string, value any) error {
	if value == nil {
		return fmt.Errorf("value for field %s is nil", field)
	}

	switch field {
	case "default_deny":
		return u.applyBoolConfig(field, value, u.mgr.SetDefaultDeny)
	case "allow_return_traffic":
		return u.applyBoolConfig(field, value, u.mgr.SetAllowReturnTraffic)
	case "allow_icmp":
		return u.applyBoolConfig(field, value, u.mgr.SetAllowICMP)
	case "strict_protocol":
		return u.applyBoolConfig(field, value, u.mgr.SetStrictProto)
	case "strict_tcp":
		return u.applyBoolConfig(field, value, u.mgr.SetStrictTCP)
	case "syn_limit":
		return u.applyBoolConfig(field, value, u.mgr.SetSYNLimit)
	case "bogon_filter":
		return u.applyBoolConfig(field, value, u.mgr.SetBogonFilter)
	case "drop_fragments":
		return u.applyBoolConfig(field, value, u.mgr.SetDropFragments)
	case "enable_af_xdp":
		return u.applyBoolConfig(field, value, u.mgr.SetEnableAFXDP)
	case "conntrack_enabled":
		return u.applyBoolConfig(field, value, u.mgr.SetConntrack)
	case "rate_limit_enabled":
		return u.applyBoolConfig(field, value, u.mgr.SetEnableRateLimit)
	default:
		return fmt.Errorf("unknown config field: %s", field)
	}
}

// applyBoolConfig applies a boolean config value.
// applyBoolConfig 应用布尔配置值。
func (u *IncrementalUpdater) applyBoolConfig(field string, value any, setter func(bool) error) error {
	v, ok := value.(bool)
	if !ok {
		return fmt.Errorf("invalid type for %s: expected bool, got %T", field, value)
	}
	return setter(v)
}

// HasChanges returns true if there are any changes to apply.
// HasChanges 如果有变更需要应用则返回 true。
func (d *ConfigDiff) HasChanges() bool {
	return len(d.GlobalConfigChanges) > 0 ||
		len(d.BlacklistAdded) > 0 ||
		len(d.BlacklistRemoved) > 0 ||
		len(d.WhitelistAdded) > 0 ||
		len(d.WhitelistRemoved) > 0 ||
		len(d.IPPortAdded) > 0 ||
		len(d.IPPortRemoved) > 0 ||
		len(d.RateLimitAdded) > 0 ||
		len(d.RateLimitRemoved) > 0 ||
		len(d.RateLimitUpdated) > 0
}

// Summary returns a human-readable summary of the changes.
// Summary 返回变更的可读摘要。
func (d *ConfigDiff) Summary() string {
	var parts []string

	if len(d.GlobalConfigChanges) > 0 {
		parts = append(parts, fmt.Sprintf("%d config changes", len(d.GlobalConfigChanges)))
	}
	if len(d.BlacklistAdded) > 0 {
		parts = append(parts, fmt.Sprintf("%d blacklist additions", len(d.BlacklistAdded)))
	}
	if len(d.BlacklistRemoved) > 0 {
		parts = append(parts, fmt.Sprintf("%d blacklist removals", len(d.BlacklistRemoved)))
	}
	if len(d.WhitelistAdded) > 0 {
		parts = append(parts, fmt.Sprintf("%d whitelist additions", len(d.WhitelistAdded)))
	}
	if len(d.WhitelistRemoved) > 0 {
		parts = append(parts, fmt.Sprintf("%d whitelist removals", len(d.WhitelistRemoved)))
	}
	if len(d.IPPortAdded) > 0 {
		parts = append(parts, fmt.Sprintf("%d IP+Port additions", len(d.IPPortAdded)))
	}
	if len(d.IPPortRemoved) > 0 {
		parts = append(parts, fmt.Sprintf("%d IP+Port removals", len(d.IPPortRemoved)))
	}

	if len(parts) == 0 {
		return "No changes detected"
	}
	return stringsJoin(parts, ", ")
}

// Helper function to join strings (to avoid importing strings package).
// 辅助函数用于连接字符串（避免导入 strings 包）。
func stringsJoin(elems []string, sep string) string {
	if len(elems) == 0 {
		return ""
	}
	result := elems[0]
	for i := 1; i < len(elems); i++ {
		result += sep + elems[i]
	}
	return result
}
