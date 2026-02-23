package logengine

import (
	"fmt"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/netxfw/netxfw/internal/plugins/types"
	"github.com/netxfw/netxfw/internal/utils/logger"
	"github.com/netxfw/netxfw/pkg/sdk"
	"github.com/stretchr/testify/assert"
)

// MockActionHandler records calls for verification
// MockActionHandler 记录调用以供验证
type MockActionHandler struct {
	BlockedIPs  []string
	ActionTypes []ActionType
}

// Block implements the ActionHandler interface
// Block 实现 ActionHandler 接口
func (m *MockActionHandler) Block(ip netip.Addr, actionType ActionType, ttl time.Duration) error {
	m.BlockedIPs = append(m.BlockedIPs, ip.String())
	m.ActionTypes = append(m.ActionTypes, actionType)
	fmt.Printf("MockBlock: %s, Action: %d, TTL: %v\n", ip, actionType, ttl)
	return nil
}

// Stop implements the ActionHandler interface
// Stop 实现 ActionHandler 接口
func (m *MockActionHandler) Stop() {}

// TestLogEngine_RuleMatching tests the rule matching logic
// TestLogEngine_RuleMatching 测试规则匹配逻辑
func TestLogEngine_RuleMatching(t *testing.T) {
	// 1. Setup Mock Handler
	// 1. 设置 Mock Handler
	mockHandler := &MockActionHandler{}

	// 2. Create LogEngine Config
	// 2. 创建 LogEngine 配置
	cfg := types.LogEngineConfig{
		Enabled: true,
		Workers: 1,
		Rules: []types.LogEngineRule{
			{
				ID:         "test_rule_static",
				Expression: `log("failed") && log("root")`,
				Action:     "2", // Static Block
			},
			{
				ID:         "test_rule_dynamic",
				Expression: `log("invalid user")`,
				Action:     "1", // Dynamic Block
				TTL:        "1m",
			},
			{
				ID:         "test_rule_threshold",
				Expression: `log("authentication error")`,
				Action:     "2",
				Threshold:  2,
				Interval:   60,
			},
		},
	}

	// 3. Initialize Engine
	// 3. 初始化引擎
	le := New(cfg, logger.Get(nil), mockHandler)

	// 4. Simulate Log Events
	// 4. 模拟日志事件
	// Case A: Should Match Static
	// 情况 A: 应该匹配静态规则
	event1 := LogEvent{
		Line:      "password failed for user root from 192.168.1.100",
		Source:    "/var/log/auth.log",
		Timestamp: time.Now(),
	}

	// Case B: Should Match Dynamic
	// 情况 B: 应该匹配动态规则
	event2 := LogEvent{
		Line:      "Invalid user admin from 10.0.0.5",
		Source:    "/var/log/auth.log",
		Timestamp: time.Now(),
	}

	// Case C: No Match
	// 情况 C: 无匹配
	event3 := LogEvent{
		Line:      "Accepted password for user root from 192.168.1.200",
		Source:    "/var/log/auth.log",
		Timestamp: time.Now(),
	}

	// Manually inject events into processing logic (bypassing tailer for unit test)
	// We need to expose a way to test 'evaluate' or just call the worker logic.
	// Since 'worker' is private, we can test 'ruleEngine.Evaluate' directly.
	// 手动将事件注入处理逻辑（绕过 tailer 进行单元测试）
	// 我们需要暴露一种测试 'evaluate' 的方法或直接调用 worker 逻辑
	// 由于 'worker' 是私有的，我们可以直接测试 'ruleEngine.Evaluate'

	// Test Event 1
	// 测试事件 1
	ip1 := netip.MustParseAddr("192.168.1.100")
	action, _, ruleID, matched := le.RuleEngine().Evaluate(ip1, event1)
	if !matched {
		t.Errorf("Event 1 should match")
	}
	if action != ActionStatic {
		t.Errorf("Event 1 should be ActionStatic, got %v", action)
	}
	if ruleID != "test_rule_static" {
		t.Errorf("Event 1 matched wrong rule: %s", ruleID)
	}

	// Test Event 2
	// 测试事件 2
	ip2 := netip.MustParseAddr("10.0.0.5")
	action2, ttl2, ruleID2, matched2 := le.RuleEngine().Evaluate(ip2, event2)
	if !matched2 {
		t.Errorf("Event 2 should match")
	}
	if action2 != ActionDynamic {
		t.Errorf("Event 2 should be ActionDynamic, got %v", action2)
	}
	if ttl2 != time.Minute {
		t.Errorf("Event 2 TTL should be 1m, got %v", ttl2)
	}
	if ruleID2 != "test_rule_dynamic" {
		t.Errorf("Event 2 matched wrong rule: %s", ruleID2)
	}

	// Test Event 3
	// 测试事件 3
	ip3 := netip.MustParseAddr("192.168.1.200")
	_, _, _, matched3 := le.RuleEngine().Evaluate(ip3, event3)
	if matched3 {
		t.Errorf("Event 3 should NOT match")
	}

	// Case D: Threshold Logic
	// 情况 D: 阈值逻辑
	// First Hit
	// 第一次命中
	ip4 := netip.MustParseAddr("1.1.1.1")
	event4a := LogEvent{Line: "authentication error 1", Source: "syslog", Timestamp: time.Now()}
	_, _, _, matched4a := le.RuleEngine().Evaluate(ip4, event4a)
	if matched4a {
		t.Errorf("Threshold rule should NOT match on 1st hit")
	}

	// Second Hit (Should NOT Trigger if Threshold=2 means >2)
	// 第二次命中（如果 Threshold=2 意味着 >2，则不应触发）
	event4b := LogEvent{Line: "authentication error 2", Source: "syslog", Timestamp: time.Now()}
	_, _, _, matched4b := le.RuleEngine().Evaluate(ip4, event4b)
	if matched4b {
		t.Errorf("Threshold rule should NOT match on 2nd hit (2 > 2 is false)")
	}

	// Third Hit (Should Trigger)
	// 第三次命中（应该触发）
	event4c := LogEvent{Line: "authentication error 3", Source: "syslog", Timestamp: time.Now()}
	action4c, _, ruleID4c, matched4c := le.RuleEngine().Evaluate(ip4, event4c)
	if !matched4c {
		t.Errorf("Threshold rule SHOULD match on 3rd hit (3 > 2 is true)")
	}
	if ruleID4c != "test_rule_threshold" {
		t.Errorf("Matched wrong rule for threshold: %s", ruleID4c)
	}
	if action4c != ActionStatic {
		t.Errorf("Should be static block")
	}

	fmt.Println("✅ RuleEngine matching logic passed (including Threshold)")
}

// TestXDPActionHandler_Async tests the async action handler
// TestXDPActionHandler_Async 测试异步动作处理器
func TestXDPActionHandler_Async(t *testing.T) {
	// Create a handler with a nil manager (we just want to test the channel logic)
	// Note: In real run, run() checks for nil manager and returns, so it won't crash.
	// 创建一个使用 nil manager 的处理器（我们只想测试通道逻辑）
	// 注意：在实际运行中，run() 检查 nil manager 并返回，所以不会崩溃
	handler := NewXDPActionHandler(nil, "/tmp/lock_list.txt")

	// Push a block request
	// 推送一个阻止请求
	ip := netip.MustParseAddr("1.2.3.4")
	err := handler.Block(ip, ActionStatic, 0)
	if err != nil {
		t.Errorf("Block should not return error on enqueue: %v", err)
	}

	// Wait a bit to ensure no panic in background worker
	// 等待一会儿以确保后台 worker 不会崩溃
	time.Sleep(100 * time.Millisecond)
	handler.Stop()
	fmt.Println("✅ Async ActionHandler enqueue passed")
}

// TestPersistenceLogic_Mock tests the file writing logic
// TestPersistenceLogic_Mock 测试文件写入逻辑
func TestPersistenceLogic_Mock(t *testing.T) {
	// Verify the file writing logic from xdp_manager (Simulated)
	// We duplicate the logic here just to verify the 'os' calls work as expected
	// 验证 xdp_manager 的文件写入逻辑（模拟）
	// 我们在这里复制逻辑只是为了验证 'os' 调用按预期工作
	tmpFile := "test_rules.deny.txt"
	defer os.Remove(tmpFile)

	cidr := "1.2.3.4/32"

	// Use O_APPEND to add to the end of the file
	// 使用 O_APPEND 在文件末尾添加
	f, err := os.OpenFile(tmpFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatalf("Failed to open file: %v", err)
	}
	if _, err := f.WriteString(cidr + "\n"); err != nil {
		f.Close()
		t.Fatalf("Failed to write: %v", err)
	}
	f.Close()

	// Verify content
	// 验证内容
	content, _ := os.ReadFile(tmpFile)
	if string(content) != "1.2.3.4/32\n" {
		t.Errorf("Content mismatch: %s", string(content))
	}

	// Append another
	// 追加另一个
	f, _ = os.OpenFile(tmpFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	f.WriteString("5.6.7.8/32\n")
	f.Close()

	content, _ = os.ReadFile(tmpFile)
	expected := "1.2.3.4/32\n5.6.7.8/32\n"
	if string(content) != expected {
		t.Errorf("Append failed. Got:\n%s", string(content))
	}

	fmt.Println("✅ Persistence file logic verification passed")
}

// TestLogEngine_LongWindow tests long window configuration
// TestLogEngine_LongWindow 测试长窗口配置
func TestLogEngine_LongWindow(t *testing.T) {
	// 1. Setup Mock Handler
	// 1. 设置 Mock Handler
	mockHandler := &MockActionHandler{}

	// 2. Create Config with 1 hour window rule
	// 2. 创建带有 1 小时窗口规则的配置
	cfg := types.LogEngineConfig{
		Enabled: true,
		Workers: 1,
		Rules: []types.LogEngineRule{
			{
				ID:         "test_rule_1h",
				Expression: `log("failed")`,
				Action:     "2",
				Threshold:  2,    // > 2
				Interval:   3600, // 1 hour
			},
		},
	}

	le := New(cfg, logger.Get(nil), mockHandler)
	ip := netip.MustParseAddr("2.2.2.2")
	event := LogEvent{Line: "failed login", Source: "auth.log", Timestamp: time.Now()}

	// Hit 1
	// 命中 1
	_, _, _, matched := le.RuleEngine().Evaluate(ip, event)
	if matched {
		t.Errorf("Should not match on 1st hit")
	}

	// Hit 2
	// 命中 2
	_, _, _, matched = le.RuleEngine().Evaluate(ip, event)
	if matched {
		t.Errorf("Should not match on 2nd hit")
	}

	// Hit 3
	// 命中 3
	_, _, _, matched = le.RuleEngine().Evaluate(ip, event)
	if !matched {
		t.Errorf("Should match on 3rd hit with 3600s window")
	}

	fmt.Println("✅ 1-Hour Window configuration accepted and working for immediate hits")
}

// TestCounter_DynamicConfig tests dynamic counter configuration
// TestCounter_DynamicConfig 测试动态计数器配置
func TestCounter_DynamicConfig(t *testing.T) {
	// Verify that MaxWindow config is respected
	// 验证 MaxWindow 配置被遵守
	cfg := types.LogEngineConfig{
		Enabled:   true,
		MaxWindow: 7200, // 2 hours
		Rules:     []types.LogEngineRule{},
	}

	mockHandler := &MockActionHandler{}
	le := New(cfg, logger.Get(nil), mockHandler)

	if le.Counter().MaxWindowSeconds() != 7200 {
		t.Errorf("Expected maxWindowSeconds to be 7200, got %d", le.Counter().MaxWindowSeconds())
	}

	fmt.Println("✅ Dynamic Counter Configuration verified")
}

// TestLogEnginePlugin_Name tests plugin name
// TestLogEnginePlugin_Name 测试插件名称
func TestLogEnginePlugin_Name(t *testing.T) {
	p := &LogEnginePlugin{}
	assert.Equal(t, "log_engine", p.Name())
}

// TestLogEnginePlugin_Type tests plugin type
// TestLogEnginePlugin_Type 测试插件类型
func TestLogEnginePlugin_Type(t *testing.T) {
	p := &LogEnginePlugin{}
	assert.Equal(t, sdk.PluginTypeExtension, p.Type())
}

// TestLogEnginePlugin_DefaultConfig tests default config
// TestLogEnginePlugin_DefaultConfig 测试默认配置
func TestLogEnginePlugin_DefaultConfig(t *testing.T) {
	p := &LogEnginePlugin{}
	cfg := p.DefaultConfig()
	assert.IsType(t, types.LogEngineConfig{}, cfg)
	logCfg := cfg.(types.LogEngineConfig)
	assert.False(t, logCfg.Enabled)
	assert.Equal(t, 4, logCfg.Workers)
}

// TestLogEnginePlugin_Validate_Disabled tests validation when disabled
// TestLogEnginePlugin_Validate_Disabled 测试禁用时的验证
func TestLogEnginePlugin_Validate_Disabled(t *testing.T) {
	p := &LogEnginePlugin{}
	cfg := &types.GlobalConfig{
		LogEngine: types.LogEngineConfig{
			Enabled: false,
		},
	}
	err := p.Validate(cfg)
	assert.NoError(t, err)
}

// TestLogEnginePlugin_Validate_NoRules tests validation with no rules
// TestLogEnginePlugin_Validate_NoRules 测试无规则时的验证
func TestLogEnginePlugin_Validate_NoRules(t *testing.T) {
	p := &LogEnginePlugin{}
	cfg := &types.GlobalConfig{
		LogEngine: types.LogEngineConfig{
			Enabled: true,
			Rules:   []types.LogEngineRule{},
		},
	}
	err := p.Validate(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no rules")
}

// TestLogEnginePlugin_Validate_Valid tests validation with valid config
// TestLogEnginePlugin_Validate_Valid 测试有效配置的验证
func TestLogEnginePlugin_Validate_Valid(t *testing.T) {
	p := &LogEnginePlugin{}
	cfg := &types.GlobalConfig{
		LogEngine: types.LogEngineConfig{
			Enabled: true,
			Rules: []types.LogEngineRule{
				{ID: "test", Expression: `log("test")`, Action: "2"},
			},
		},
	}
	err := p.Validate(cfg)
	assert.NoError(t, err)
}

// TestLogEnginePlugin_Stop tests plugin stop
// TestLogEnginePlugin_Stop 测试插件停止
func TestLogEnginePlugin_Stop(t *testing.T) {
	p := &LogEnginePlugin{}
	err := p.Stop()
	assert.NoError(t, err)
}

// TestLogEnginePlugin_Stop_WithEngine tests plugin stop with engine
// TestLogEnginePlugin_Stop_WithEngine 测试带引擎的插件停止
func TestLogEnginePlugin_Stop_WithEngine(t *testing.T) {
	p := &LogEnginePlugin{
		engine: New(types.LogEngineConfig{Enabled: true}, logger.Get(nil), &MockActionHandler{}),
	}
	err := p.Stop()
	assert.NoError(t, err)
}

// TestLogEnginePlugin_Start_Disabled tests plugin start when disabled
// TestLogEnginePlugin_Start_Disabled 测试禁用时的插件启动
func TestLogEnginePlugin_Start_Disabled(t *testing.T) {
	p := &LogEnginePlugin{
		config: types.LogEngineConfig{
			Enabled: false,
		},
	}
	ctx := &sdk.PluginContext{
		Config: &types.GlobalConfig{
			LogEngine: types.LogEngineConfig{
				Enabled: false,
			},
		},
		SDK: &sdk.SDK{},
	}
	err := p.Start(ctx)
	assert.NoError(t, err)
}
