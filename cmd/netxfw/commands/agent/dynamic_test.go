package agent

import (
	"testing"

	"github.com/netxfw/netxfw/cmd/netxfw/commands/common"
	"github.com/stretchr/testify/assert"
)

// TestDynamicCmd tests the dynamic command structure.
// TestDynamicCmd 测试动态命令结构。
func TestDynamicCmd(t *testing.T) {
	assert.NotNil(t, DynamicCmd)
	assert.Equal(t, "dynamic", DynamicCmd.Use)
	assert.Contains(t, DynamicCmd.Aliases, "dyn")
}

// TestDynamicAddCmd tests the dynamic add command.
// TestDynamicAddCmd 测试动态添加命令。
func TestDynamicAddCmd(t *testing.T) {
	assert.NotNil(t, dynamicAddCmd)
	assert.Equal(t, "add <ip>", dynamicAddCmd.Use)
}

// TestDynamicDelCmd tests the dynamic del command.
// TestDynamicDelCmd 测试动态删除命令。
func TestDynamicDelCmd(t *testing.T) {
	assert.NotNil(t, dynamicDelCmd)
	assert.Equal(t, "del <ip>", dynamicDelCmd.Use)
	assert.Contains(t, dynamicDelCmd.Aliases, "delete")
}

// TestDynamicListCmd tests the dynamic list command.
// TestDynamicListCmd 测试动态列表命令。
func TestDynamicListCmd(t *testing.T) {
	assert.NotNil(t, dynamicListCmd)
	assert.Equal(t, "list", dynamicListCmd.Use)
}

// TestDynamicCommandIntegration tests dynamic command integration.
// TestDynamicCommandIntegration 测试动态命令集成。
func TestDynamicCommandIntegration(t *testing.T) {
	common.SetMockSDK(setupMockSDKWithExpectations())

	tests := []struct {
		name     string
		args     []string
		wantErr  bool
		contains string
	}{
		{
			name:     "DynamicHelp",
			args:     []string{"--help"},
			wantErr:  false,
			contains: "Dynamic blacklist",
		},
		{
			name:     "AddHelp",
			args:     []string{"add", "--help"},
			wantErr:  false,
			contains: "Add IP to dynamic blacklist",
		},
		{
			name:     "DelHelp",
			args:     []string{"del", "--help"},
			wantErr:  false,
			contains: "Delete IP from dynamic blacklist",
		},
		{
			name:     "ListHelp",
			args:     []string{"list", "--help"},
			wantErr:  false,
			contains: "entries in dynamic blacklist",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			common.SetMockSDK(setupMockSDKWithExpectations())
			output, err := executeCmd(DynamicCmd, tt.args...)
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

// TestDynamicAddWithTTL tests dynamic add with TTL validation.
// TestDynamicAddWithTTL 测试动态添加的 TTL 验证。
func TestDynamicAddWithTTL(t *testing.T) {
	tests := []struct {
		name    string
		ip      string
		ttl     string
		wantErr bool
	}{
		{
			name:    "ValidIPv4_1h",
			ip:      "192.168.1.100",
			ttl:     "1h",
			wantErr: false,
		},
		{
			name:    "ValidIPv4_24h",
			ip:      "10.0.0.1",
			ttl:     "24h",
			wantErr: false,
		},
		{
			name:    "ValidIPv6_30m",
			ip:      "2001:db8::1",
			ttl:     "30m",
			wantErr: false,
		},
		{
			name:    "ValidIPv4_1h30m",
			ip:      "172.16.0.1",
			ttl:     "1h30m",
			wantErr: false,
		},
		{
			name:    "ValidIPv4_365d",
			ip:      "192.168.2.1",
			ttl:     "8760h",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			common.SetMockSDK(setupMockSDKWithExpectations())

			args := []string{"add", tt.ip}
			if tt.ttl != "" {
				args = append(args, "--ttl", tt.ttl)
			}

			_, err := executeCmd(DynamicCmd, args...)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestDynamicDel tests dynamic delete command.
// TestDynamicDel 测试动态删除命令。
func TestDynamicDel(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{
			name:    "DelIPv4",
			args:    []string{"del", "192.168.1.100"},
			wantErr: false,
		},
		{
			name:    "DeleteIPv4_Alias",
			args:    []string{"delete", "192.168.1.101"},
			wantErr: false,
		},
		{
			name:    "DelIPv6",
			args:    []string{"del", "2001:db8::1"},
			wantErr: false,
		},
		{
			name:    "DelIPv4_CIDR",
			args:    []string{"del", "10.0.0.0/24"},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			common.SetMockSDK(setupMockSDKWithExpectations())
			_, err := executeCmd(DynamicCmd, tt.args...)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestDynamicList tests dynamic list command.
// TestDynamicList 测试动态列表命令。
func TestDynamicList(t *testing.T) {
	common.SetMockSDK(setupMockSDKWithExpectations())

	_, err := executeCmd(DynamicCmd, "list")
	assert.NoError(t, err)
}

// TestDynamicCommandAliases tests command aliases.
// TestDynamicCommandAliases 测试命令别名。
func TestDynamicCommandAliases(t *testing.T) {
	// Test dyn alias
	// 测试 dyn 别名
	assert.Contains(t, DynamicCmd.Aliases, "dyn")

	// Test delete alias for del
	// 测试 del 的 delete 别名
	assert.Contains(t, dynamicDelCmd.Aliases, "delete")
}
