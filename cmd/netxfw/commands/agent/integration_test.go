package agent

import (
	"bytes"
	"sync"
	"testing"
	"time"

	"github.com/netxfw/netxfw/cmd/netxfw/commands/common"
	"github.com/netxfw/netxfw/pkg/sdk"
	"github.com/netxfw/netxfw/pkg/sdk/mock"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// cmdMutex protects command execution from concurrent access
// cmdMutex 保护命令执行免受并发访问
var cmdMutex sync.Mutex

// executeCommand executes a cobra command and returns output.
// executeCommand 执行 cobra 命令并返回输出。
func executeCmd(cmd *cobra.Command, args ...string) (string, error) {
	cmdMutex.Lock()
	defer cmdMutex.Unlock()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return buf.String(), err
}

// setupMockSDKWithExpectations creates a mock SDK with default expectations.
// setupMockSDKWithExpectations 创建带有默认期望的 mock SDK。
func setupMockSDKWithExpectations() *sdk.SDK {
	m := mock.NewMockSDK()
	mock.SetupMockBlacklist(m)
	mock.SetupMockWhitelist(m)
	mock.SetupMockRule(m)
	return m
}

// TestRuleAddCommandIntegration tests rule add command with various inputs.
// TestRuleAddCommandIntegration 测试规则添加命令的各种输入。
func TestRuleAddCommandIntegration(t *testing.T) {
	common.SetMockSDK(setupMockSDKWithExpectations())

	tests := []struct {
		name     string
		args     []string
		wantErr  bool
		contains string
	}{
		{
			name:     "AddIPv4ToBlacklist",
			args:     []string{"add", "192.168.1.1", "deny"},
			wantErr:  false,
			contains: "Blacklist",
		},
		{
			name:     "AddIPv4ToWhitelist",
			args:     []string{"add", "192.168.1.2", "allow"},
			wantErr:  false,
			contains: "Whitelist",
		},
		{
			name:     "AddIPv4WithPort",
			args:     []string{"add", "192.168.1.3:8080", "deny"},
			wantErr:  false,
			contains: "Rule",
		},
		{
			name:     "AddIPv6Address",
			args:     []string{"add", "2001:db8::1", "deny"},
			wantErr:  false,
			contains: "Blacklist",
		},
		{
			name:     "AddCIDR",
			args:     []string{"add", "10.0.0.0/24", "deny"},
			wantErr:  false,
			contains: "Blacklist",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset mock for each test
			// 为每个测试重置 mock
			common.SetMockSDK(setupMockSDKWithExpectations())
			output, err := executeCmd(RuleCmd, tt.args...)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			if tt.contains != "" {
				assert.Contains(t, output, tt.contains)
			}
		})
	}
}

// TestRuleListCommandIntegration tests rule list command.
// TestRuleListCommandIntegration 测试规则列表命令。
func TestRuleListCommandIntegration(t *testing.T) {
	common.SetMockSDK(setupMockSDKWithExpectations())

	tests := []struct {
		name     string
		args     []string
		wantErr  bool
		contains string
	}{
		{
			name:     "ListAllRules",
			args:     []string{"list"},
			wantErr:  false,
			contains: "Whitelist",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			common.SetMockSDK(setupMockSDKWithExpectations())
			output, err := executeCmd(RuleCmd, tt.args...)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			if tt.contains != "" {
				assert.Contains(t, output, tt.contains)
			}
		})
	}
}

// TestRuleRemoveCommandIntegration tests rule remove command.
// TestRuleRemoveCommandIntegration 测试规则删除命令。
func TestRuleRemoveCommandIntegration(t *testing.T) {
	common.SetMockSDK(setupMockSDKWithExpectations())

	tests := []struct {
		name     string
		args     []string
		wantErr  bool
		contains string
	}{
		{
			name:     "RemoveIP",
			args:     []string{"remove", "192.168.1.1"},
			wantErr:  false,
			contains: "Removed",
		},
		{
			name:     "RemoveIPWithPort",
			args:     []string{"remove", "192.168.1.1:8080"},
			wantErr:  false,
			contains: "Removed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			common.SetMockSDK(setupMockSDKWithExpectations())
			output, err := executeCmd(RuleCmd, tt.args...)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			if tt.contains != "" {
				assert.Contains(t, output, tt.contains)
			}
		})
	}
}

// TestQuickBlockCommandIntegration tests quick block command.
// TestQuickBlockCommandIntegration 测试快速封禁命令。
func TestQuickBlockCommandIntegration(t *testing.T) {
	common.SetMockSDK(setupMockSDKWithExpectations())

	tests := []struct {
		name     string
		args     []string
		wantErr  bool
		contains string
	}{
		{
			name:     "BlockIPv4",
			args:     []string{"1.2.3.4"},
			wantErr:  false,
			contains: "",
		},
		{
			name:     "BlockIPv6",
			args:     []string{"2001:db8::1"},
			wantErr:  false,
			contains: "",
		},
		{
			name:     "BlockCIDR",
			args:     []string{"10.0.0.0/24"},
			wantErr:  false,
			contains: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			common.SetMockSDK(setupMockSDKWithExpectations())
			output, err := executeCmd(QuickBlockCmd, tt.args...)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			if tt.contains != "" {
				assert.Contains(t, output, tt.contains)
			}
		})
	}
}

// TestQuickUnlockCommandIntegration tests quick unlock command.
// TestQuickUnlockCommandIntegration 测试快速解封命令。
func TestQuickUnlockCommandIntegration(t *testing.T) {
	common.SetMockSDK(setupMockSDKWithExpectations())

	tests := []struct {
		name     string
		args     []string
		wantErr  bool
		contains string
	}{
		{
			name:     "UnlockIPv4",
			args:     []string{"1.2.3.4"},
			wantErr:  false,
			contains: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			common.SetMockSDK(setupMockSDKWithExpectations())
			output, err := executeCmd(QuickUnlockCmd, tt.args...)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			if tt.contains != "" {
				assert.Contains(t, output, tt.contains)
			}
		})
	}
}

// TestQuickAllowCommandIntegration tests quick allow command.
// TestQuickAllowCommandIntegration 测试快速允许命令。
func TestQuickAllowCommandIntegration(t *testing.T) {
	common.SetMockSDK(setupMockSDKWithExpectations())

	tests := []struct {
		name     string
		args     []string
		wantErr  bool
		contains string
	}{
		{
			name:     "AllowIPv4",
			args:     []string{"1.2.3.4"},
			wantErr:  false,
			contains: "",
		},
		{
			name:     "AllowIPv4WithPort",
			args:     []string{"1.2.3.4", "80"},
			wantErr:  false,
			contains: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			common.SetMockSDK(setupMockSDKWithExpectations())
			output, err := executeCmd(QuickAllowCmd, tt.args...)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			if tt.contains != "" {
				assert.Contains(t, output, tt.contains)
			}
		})
	}
}

// TestPortCommandIntegration tests port command.
// TestPortCommandIntegration 测试端口命令。
func TestPortCommandIntegration(t *testing.T) {
	common.SetMockSDK(setupMockSDKWithExpectations())

	tests := []struct {
		name     string
		args     []string
		wantErr  bool
		contains string
	}{
		{
			name:     "RemovePort",
			args:     []string{"remove", "8080"},
			wantErr:  false,
			contains: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			common.SetMockSDK(setupMockSDKWithExpectations())
			output, err := executeCmd(PortCmd, tt.args...)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			if tt.contains != "" {
				assert.Contains(t, output, tt.contains)
			}
		})
	}
}

// TestLimitCommandIntegration tests limit command.
// TestLimitCommandIntegration 测试限速命令。
func TestLimitCommandIntegration(t *testing.T) {
	common.SetMockSDK(setupMockSDKWithExpectations())

	tests := []struct {
		name     string
		args     []string
		wantErr  bool
		contains string
	}{
		{
			name:     "AddRateLimit",
			args:     []string{"add", "192.168.1.1", "1000", "2000"},
			wantErr:  false,
			contains: "",
		},
		{
			name:     "ListRateLimits",
			args:     []string{"list"},
			wantErr:  false,
			contains: "",
		},
		{
			name:     "RemoveRateLimit",
			args:     []string{"remove", "192.168.1.1"},
			wantErr:  false,
			contains: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			common.SetMockSDK(setupMockSDKWithExpectations())
			output, err := executeCmd(LimitCmd, tt.args...)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			if tt.contains != "" {
				assert.Contains(t, output, tt.contains)
			}
		})
	}
}

// TestCommandExecutionTime tests that commands execute within reasonable time.
// TestCommandExecutionTime 测试命令在合理时间内执行。
func TestCommandExecutionTime(t *testing.T) {
	common.SetMockSDK(setupMockSDKWithExpectations())

	commands := []struct {
		name string
		cmd  *cobra.Command
		args []string
	}{
		{"RuleList", RuleCmd, []string{"list"}},
		{"LimitList", LimitCmd, []string{"list"}},
	}

	for _, tc := range commands {
		t.Run(tc.name, func(t *testing.T) {
			common.SetMockSDK(setupMockSDKWithExpectations())
			start := time.Now()
			_, err := executeCmd(tc.cmd, tc.args...)
			elapsed := time.Since(start)

			require.NoError(t, err)
			assert.Less(t, elapsed.Milliseconds(), int64(1000), "Command should execute within 1 second")
		})
	}
}

// TestConcurrentCommandExecution tests concurrent command execution.
// TestConcurrentCommandExecution 测试并发命令执行。
func TestConcurrentCommandExecution(t *testing.T) {
	common.SetMockSDK(setupMockSDKWithExpectations())

	const numGoroutines = 10
	done := make(chan bool, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer func() { done <- true }()
			// Note: In concurrent tests, we don't reset MockSDK in each goroutine
			// to avoid race conditions. The mock is set once before the test.
			// 注意：在并发测试中，我们不在每个 goroutine 中重置 MockSDK
			// 以避免竞争条件。Mock 在测试前设置一次。
			_, err := executeCmd(RuleCmd, "list")
			assert.NoError(t, err)
		}(i)
	}

	for i := 0; i < numGoroutines; i++ {
		<-done
	}
}

// TestCommandHelpOutput tests that all commands have proper help output.
// TestCommandHelpOutput 测试所有命令都有正确的帮助输出。
func TestCommandHelpOutput(t *testing.T) {
	commands := []struct {
		name string
		cmd  *cobra.Command
	}{
		{"Rule", RuleCmd},
		{"Port", PortCmd},
		{"Limit", LimitCmd},
		{"Security", SecurityCmd},
		{"System", SystemCmd},
		{"Web", WebCmd},
		{"Perf", PerfCmd},
		{"Version", VersionCmd},
		{"Block", QuickBlockCmd},
		{"Unlock", QuickUnlockCmd},
		{"Allow", QuickAllowCmd},
	}

	for _, tc := range commands {
		t.Run(tc.name, func(t *testing.T) {
			output, err := executeCmd(tc.cmd, "--help")
			require.NoError(t, err)
			assert.NotEmpty(t, output)
			assert.Contains(t, output, "Usage:")
		})
	}
}

// TestRuleImportCommand tests rule import functionality.
// TestRuleImportCommand 测试规则导入功能。
func TestRuleImportCommand(t *testing.T) {
	common.SetMockSDK(setupMockSDKWithExpectations())

	// Test with help flag to avoid file operations
	// 使用帮助标志测试以避免文件操作
	output, err := executeCmd(RuleCmd, "import", "--help")
	require.NoError(t, err)
	assert.Contains(t, output, "Import rules")
}

// TestCommandFlagParsing tests flag parsing for various commands.
// TestCommandFlagParsing 测试各种命令的标志解析。
func TestCommandFlagParsing(t *testing.T) {
	common.SetMockSDK(setupMockSDKWithExpectations())

	tests := []struct {
		name string
		cmd  *cobra.Command
		args []string
	}{
		{"RuleList", RuleCmd, []string{"list"}},
		{"LimitList", LimitCmd, []string{"list"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			common.SetMockSDK(setupMockSDKWithExpectations())
			_, err := executeCmd(tt.cmd, tt.args...)
			require.NoError(t, err)
		})
	}
}

// TestErrorHandling tests error handling in commands.
// TestErrorHandling 测试命令中的错误处理。
func TestErrorHandling(t *testing.T) {
	tests := []struct {
		name string
		cmd  *cobra.Command
		args []string
	}{
		{"RuleAddMissingArg", RuleCmd, []string{"add"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := executeCmd(tt.cmd, tt.args...)
			assert.Error(t, err)
		})
	}
}

// TestSDKInterfaceCompliance tests that mock SDK implements all required interfaces.
// TestSDKInterfaceCompliance 测试 mock SDK 实现了所有必需的接口。
func TestSDKInterfaceCompliance(t *testing.T) {
	m := setupMockSDKWithExpectations()
	var _ sdk.BlacklistAPI = m.Blacklist
	var _ sdk.WhitelistAPI = m.Whitelist
	var _ sdk.RuleAPI = m.Rule
	var _ sdk.StatsAPI = m.Stats
	var _ sdk.ConntrackAPI = m.Conntrack
}
