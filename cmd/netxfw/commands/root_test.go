package commands

import (
	"bytes"
	"testing"

	"github.com/netxfw/netxfw/cmd/netxfw/commands/agent"
	"github.com/netxfw/netxfw/cmd/netxfw/commands/common"
	"github.com/netxfw/netxfw/pkg/sdk"
	"github.com/netxfw/netxfw/pkg/sdk/mock"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

// executeCommand executes a cobra command and returns output.
// executeCommand 执行 cobra 命令并返回输出。
func executeCommand(cmd *cobra.Command, args ...string) (string, error) {
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return buf.String(), err
}

// setupMockSDK creates a mock SDK for testing.
// setupMockSDK 创建用于测试的 mock SDK。
func setupMockSDK() *sdk.SDK {
	return mock.NewMockSDK()
}

// TestRootCommand tests the root command execution.
// TestRootCommand 测试根命令执行。
func TestRootCommand(t *testing.T) {
	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetArgs([]string{"--help"})
	err := RootCmd.Execute()
	assert.NoError(t, err)
	output := buf.String()
	assert.Contains(t, output, "netxfw")
	assert.Contains(t, output, "high-performance")
}

// TestRootCommandHelp tests root command help output.
// TestRootCommandHelp 测试根命令帮助输出。
func TestRootCommandHelp(t *testing.T) {
	output, err := executeCommand(RootCmd, "--help")
	assert.NoError(t, err)
	assert.Contains(t, output, "Usage:")
	assert.Contains(t, output, "Available Commands:")
}

// TestInvalidCommand tests invalid command handling.
// TestInvalidCommand 测试无效命令处理。
func TestInvalidCommand(t *testing.T) {
	// Create a new root command to avoid side effects
	// 创建新的根命令以避免副作用
	testRoot := &cobra.Command{Use: "test"}
	testRoot.AddCommand(agent.RuleCmd)

	buf := new(bytes.Buffer)
	testRoot.SetOut(buf)
	testRoot.SetErr(buf)
	testRoot.SetArgs([]string{"invalid-command"})
	err := testRoot.Execute()
	assert.Error(t, err)
}

// TestRuleCommandIntegration tests rule command integration.
// TestRuleCommandIntegration 测试规则命令集成。
func TestRuleCommandIntegration(t *testing.T) {
	// Setup mock SDK
	// 设置 mock SDK
	common.MockSDK = setupMockSDK()

	tests := []struct {
		name     string
		args     []string
		contains string
		wantErr  bool
	}{
		{
			name:     "RuleHelp",
			args:     []string{"rule", "--help"},
			contains: "rule",
			wantErr:  false,
		},
		{
			name:     "RuleListHelp",
			args:     []string{"rule", "list", "--help"},
			contains: "List",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a fresh root command for each test to avoid state pollution
			// 为每个测试创建新的根命令以避免状态污染
			testRoot := &cobra.Command{Use: "netxfw"}
			testRoot.AddCommand(agent.RuleCmd)

			buf := new(bytes.Buffer)
			testRoot.SetOut(buf)
			testRoot.SetErr(buf)
			testRoot.SetArgs(tt.args)

			err := testRoot.Execute()
			output := buf.String()

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Contains(t, output, tt.contains)
		})
	}
}

// TestQuickCommandsIntegration tests quick command integration.
// TestQuickCommandsIntegration 测试快速命令集成。
func TestQuickCommandsIntegration(t *testing.T) {
	common.MockSDK = setupMockSDK()

	tests := []struct {
		name     string
		args     []string
		contains string
		wantErr  bool
	}{
		{
			name:     "BlockHelp",
			args:     []string{"block", "--help"},
			contains: "block",
			wantErr:  false,
		},
		{
			name:     "UnlockHelp",
			args:     []string{"unlock", "--help"},
			contains: "blacklist",
			wantErr:  false,
		},
		{
			name:     "AllowHelp",
			args:     []string{"allow", "--help"},
			contains: "whitelist",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output, err := executeCommand(RootCmd, tt.args...)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Contains(t, output, tt.contains)
		})
	}
}

// TestPortCommandIntegration tests port command integration.
// TestPortCommandIntegration 测试端口命令集成。
func TestPortCommandIntegration(t *testing.T) {
	common.MockSDK = setupMockSDK()

	tests := []struct {
		name     string
		args     []string
		contains string
		wantErr  bool
	}{
		{
			name:     "PortHelp",
			args:     []string{"port", "--help"},
			contains: "port",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output, err := executeCommand(RootCmd, tt.args...)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Contains(t, output, tt.contains)
		})
	}
}

// TestLimitCommandIntegration tests limit command integration.
// TestLimitCommandIntegration 测试限速命令集成。
func TestLimitCommandIntegration(t *testing.T) {
	common.MockSDK = setupMockSDK()

	tests := []struct {
		name     string
		args     []string
		contains string
		wantErr  bool
	}{
		{
			name:     "LimitHelp",
			args:     []string{"limit", "--help"},
			contains: "Rate limit",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output, err := executeCommand(RootCmd, tt.args...)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Contains(t, output, tt.contains)
		})
	}
}

// TestSecurityCommandIntegration tests security command integration.
// TestSecurityCommandIntegration 测试安全命令集成。
func TestSecurityCommandIntegration(t *testing.T) {
	common.MockSDK = setupMockSDK()

	tests := []struct {
		name     string
		args     []string
		contains string
		wantErr  bool
	}{
		{
			name:     "SecurityHelp",
			args:     []string{"security", "--help"},
			contains: "Security",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output, err := executeCommand(RootCmd, tt.args...)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Contains(t, output, tt.contains)
		})
	}
}

// TestSystemCommandIntegration tests system command integration.
// TestSystemCommandIntegration 测试系统命令集成。
func TestSystemCommandIntegration(t *testing.T) {
	common.MockSDK = setupMockSDK()

	tests := []struct {
		name     string
		args     []string
		contains string
		wantErr  bool
	}{
		{
			name:     "SystemHelp",
			args:     []string{"system", "--help"},
			contains: "System management commands",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output, err := executeCommand(RootCmd, tt.args...)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Contains(t, output, tt.contains)
		})
	}
}

// TestVersionCommandIntegration tests version command integration.
// TestVersionCommandIntegration 测试版本命令集成。
func TestVersionCommandIntegration(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		contains string
		wantErr  bool
	}{
		{
			name:     "VersionHelp",
			args:     []string{"version", "--help"},
			contains: "version",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output, err := executeCommand(RootCmd, tt.args...)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Contains(t, output, tt.contains)
		})
	}
}

// TestWebCommandIntegration tests web command integration.
// TestWebCommandIntegration 测试 web 命令集成。
func TestWebCommandIntegration(t *testing.T) {
	common.MockSDK = setupMockSDK()

	tests := []struct {
		name     string
		args     []string
		contains string
		wantErr  bool
	}{
		{
			name:     "WebHelp",
			args:     []string{"web", "--help"},
			contains: "web",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output, err := executeCommand(RootCmd, tt.args...)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Contains(t, output, tt.contains)
		})
	}
}

// TestPerfCommandIntegration tests perf command integration.
// TestPerfCommandIntegration 测试性能命令集成。
func TestPerfCommandIntegration(t *testing.T) {
	common.MockSDK = setupMockSDK()

	tests := []struct {
		name     string
		args     []string
		contains string
		wantErr  bool
	}{
		{
			name:     "PerfHelp",
			args:     []string{"perf", "--help"},
			contains: "Performance monitoring",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output, err := executeCommand(RootCmd, tt.args...)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Contains(t, output, tt.contains)
		})
	}
}

// TestConntrackCommandIntegration tests conntrack command integration.
// TestConntrackCommandIntegration 测试连接跟踪命令集成。
func TestConntrackCommandIntegration(t *testing.T) {
	common.MockSDK = setupMockSDK()

	tests := []struct {
		name     string
		args     []string
		contains string
		wantErr  bool
	}{
		{
			name:     "ConntrackHelp",
			args:     []string{"conntrack", "--help"},
			contains: "connection",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output, err := executeCommand(RootCmd, tt.args...)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Contains(t, output, tt.contains)
		})
	}
}

// TestCommandChaining tests that commands can be chained properly.
// TestCommandChaining 测试命令可以正确链接。
func TestCommandChaining(t *testing.T) {
	common.MockSDK = setupMockSDK()

	// Test that all subcommands are registered
	// 测试所有子命令都已注册
	commands := RootCmd.Commands()
	assert.NotEmpty(t, commands)

	// Verify expected commands exist
	// 验证预期命令存在
	expectedCommands := []string{
		"rule",
		"limit",
		"security",
		"port",
		"web",
		"block",
		"unlock",
		"allow",
		"unallow",
		"clear",
		"system",
		"perf",
		"version",
		"conntrack",
	}

	foundCommands := make(map[string]bool)
	for _, cmd := range commands {
		foundCommands[cmd.Name()] = true
	}

	for _, expected := range expectedCommands {
		assert.True(t, foundCommands[expected], "Expected command '%s' not found", expected)
	}
}

// TestPersistentFlags tests persistent flags functionality.
// TestPersistentFlags 测试持久标志功能。
func TestPersistentFlags(t *testing.T) {
	// Test config flag
	// 测试配置标志
	assert.NotNil(t, RootCmd.PersistentFlags().Lookup("config"))

	// Test mode flag
	// 测试模式标志
	assert.NotNil(t, RootCmd.PersistentFlags().Lookup("mode"))
}
