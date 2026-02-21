package xdp

import (
	"testing"

	"github.com/netxfw/netxfw/internal/plugins/types"
	"github.com/stretchr/testify/assert"
)

// TestConfigDiff_HasChanges tests the HasChanges method.
// TestConfigDiff_HasChanges 测试 HasChanges 方法。
func TestConfigDiff_HasChanges(t *testing.T) {
	// Empty diff should have no changes
	// 空差异应该没有变更
	diff := &ConfigDiff{}
	assert.False(t, diff.HasChanges())

	// Diff with global config changes
	// 有全局配置变更的差异
	diff = &ConfigDiff{
		GlobalConfigChanges: map[string]ConfigChange{
			"default_deny": {Field: "default_deny", OldValue: false, NewValue: true},
		},
	}
	assert.True(t, diff.HasChanges())

	// Diff with blacklist additions
	// 有黑名单新增的差异
	diff = &ConfigDiff{
		BlacklistAdded: []string{"10.0.0.1"},
	}
	assert.True(t, diff.HasChanges())

	// Diff with whitelist removals
	// 有白名单移除的差异
	diff = &ConfigDiff{
		WhitelistRemoved: []string{"192.168.1.1"},
	}
	assert.True(t, diff.HasChanges())
}

// TestConfigDiff_Summary tests the Summary method.
// TestConfigDiff_Summary 测试 Summary 方法。
func TestConfigDiff_Summary(t *testing.T) {
	// Empty diff
	// 空差异
	diff := &ConfigDiff{}
	assert.Equal(t, "No changes detected", diff.Summary())

	// Diff with multiple changes
	// 有多个变更的差异
	diff = &ConfigDiff{
		GlobalConfigChanges: map[string]ConfigChange{
			"default_deny": {Field: "default_deny", OldValue: false, NewValue: true},
		},
		BlacklistAdded:   []string{"10.0.0.1", "10.0.0.2"},
		WhitelistRemoved: []string{"192.168.1.1"},
	}
	summary := diff.Summary()
	assert.Contains(t, summary, "1 config changes")
	assert.Contains(t, summary, "2 blacklist additions")
	assert.Contains(t, summary, "1 whitelist removals")
}

// TestIncrementalUpdater_ComputeDiff tests the ComputeDiff method.
// TestIncrementalUpdater_ComputeDiff 测试 ComputeDiff 方法。
func TestIncrementalUpdater_ComputeDiff(t *testing.T) {
	// Create mock manager
	// 创建模拟管理器
	mgr := &Manager{}

	// Create incremental updater
	// 创建增量更新器
	updater := NewIncrementalUpdater(mgr)
	assert.NotNil(t, updater)

	// Create old and new configs
	// 创建旧配置和新配置
	oldCfg := &types.GlobalConfig{
		Base: types.BaseConfig{
			DefaultDeny:        false,
			AllowReturnTraffic: true,
			AllowICMP:          true,
			Whitelist:          []string{"192.168.1.0/24"},
		},
		Conntrack: types.ConntrackConfig{
			Enabled: true,
		},
		RateLimit: types.RateLimitConfig{
			Enabled: false,
		},
	}

	newCfg := &types.GlobalConfig{
		Base: types.BaseConfig{
			DefaultDeny:        true, // Changed / 已变更
			AllowReturnTraffic: true,
			AllowICMP:          false,                                    // Changed / 已变更
			Whitelist:          []string{"192.168.1.0/24", "10.0.0.0/8"}, // Added / 已新增
		},
		Conntrack: types.ConntrackConfig{
			Enabled: true,
		},
		RateLimit: types.RateLimitConfig{
			Enabled: true, // Changed / 已变更
		},
	}

	// Note: Maps are nil, so blacklist/whitelist comparison will be skipped
	// But global config comparison should still work
	// 注意：Map 为 nil，所以黑名单/白名单比较会被跳过
	// 但全局配置比较仍然应该工作
	diff, err := updater.ComputeDiff(oldCfg, newCfg)

	// Should succeed (maps are nil but that's handled)
	// 应该成功（Map 为 nil 但已处理）
	assert.NoError(t, err)
	assert.NotNil(t, diff)

	// Check global config changes
	// 检查全局配置变更
	assert.Contains(t, diff.GlobalConfigChanges, "default_deny")
	assert.Contains(t, diff.GlobalConfigChanges, "allow_icmp")
	assert.Contains(t, diff.GlobalConfigChanges, "rate_limit_enabled")
}

// TestIncrementalUpdater_ApplyGlobalConfigChange tests applying global config changes.
// TestIncrementalUpdater_ApplyGlobalConfigChange 测试应用全局配置变更。
func TestIncrementalUpdater_ApplyGlobalConfigChange(t *testing.T) {
	mgr := &Manager{}
	updater := NewIncrementalUpdater(mgr)

	// Test unknown field
	// 测试未知字段
	err := updater.applyGlobalConfigChange("unknown_field", true)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown config field")

	// Test nil value
	// 测试 nil 值
	err = updater.applyGlobalConfigChange("default_deny", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "is nil")

	// Test invalid type
	// 测试无效类型
	err = updater.applyGlobalConfigChange("default_deny", "not_a_bool")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid type")
}

// TestIncrementalUpdater_ApplyDiff_NilDiff tests ApplyDiff with nil diff.
// TestIncrementalUpdater_ApplyDiff_NilDiff 测试 ApplyDiff 使用 nil diff。
func TestIncrementalUpdater_ApplyDiff_NilDiff(t *testing.T) {
	mgr := &Manager{}
	updater := NewIncrementalUpdater(mgr)

	err := updater.ApplyDiff(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "diff is nil")
}

// TestIncrementalUpdater_ApplyDiff_NoChanges tests ApplyDiff with no changes.
// TestIncrementalUpdater_ApplyDiff_NoChanges 测试 ApplyDiff 没有变更。
func TestIncrementalUpdater_ApplyDiff_NoChanges(t *testing.T) {
	mgr := &Manager{}
	updater := NewIncrementalUpdater(mgr)

	diff := &ConfigDiff{}
	err := updater.ApplyDiff(diff)
	assert.NoError(t, err)
}

// TestIncrementalUpdater_NewIncrementalUpdater tests creating a new incremental updater.
// TestIncrementalUpdater_NewIncrementalUpdater 测试创建新的增量更新器。
func TestIncrementalUpdater_NewIncrementalUpdater(t *testing.T) {
	mgr := &Manager{}
	updater := NewIncrementalUpdater(mgr)
	assert.NotNil(t, updater)
	assert.Equal(t, mgr, updater.mgr)
}

// TestConfigChange tests the ConfigChange struct.
// TestConfigChange 测试 ConfigChange 结构体。
func TestConfigChange(t *testing.T) {
	change := ConfigChange{
		Field:    "default_deny",
		OldValue: false,
		NewValue: true,
	}
	assert.Equal(t, "default_deny", change.Field)
	assert.False(t, change.OldValue.(bool))
	assert.True(t, change.NewValue.(bool))
}

// TestIPPortRuleChange tests the IPPortRuleChange struct.
// TestIPPortRuleChange 测试 IPPortRuleChange 结构体。
func TestIPPortRuleChange(t *testing.T) {
	change := IPPortRuleChange{
		IP:     "192.168.1.1",
		Port:   80,
		Action: 1, // Allow
	}
	assert.Equal(t, "192.168.1.1", change.IP)
	assert.Equal(t, uint16(80), change.Port)
	assert.Equal(t, uint8(1), change.Action)
}

// TestRateLimitChange tests the RateLimitChange struct.
// TestRateLimitChange 测试 RateLimitChange 结构体。
func TestRateLimitChange(t *testing.T) {
	change := RateLimitChange{
		CIDR:  "10.0.0.0/8",
		Rate:  1000,
		Burst: 2000,
	}
	assert.Equal(t, "10.0.0.0/8", change.CIDR)
	assert.Equal(t, uint64(1000), change.Rate)
	assert.Equal(t, uint64(2000), change.Burst)
}

// TestStringsJoin tests the stringsJoin helper function.
// TestStringsJoin 测试 stringsJoin 辅助函数。
func TestStringsJoin(t *testing.T) {
	// Empty slice
	// 空切片
	assert.Equal(t, "", stringsJoin([]string{}, ", "))

	// Single element
	// 单个元素
	assert.Equal(t, "a", stringsJoin([]string{"a"}, ", "))

	// Multiple elements
	// 多个元素
	assert.Equal(t, "a, b, c", stringsJoin([]string{"a", "b", "c"}, ", "))
}
