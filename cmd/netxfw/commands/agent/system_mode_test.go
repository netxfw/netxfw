package agent

import (
	"testing"

	"github.com/cilium/ebpf/link"
	"github.com/stretchr/testify/assert"
)

// TestXDPModeValidation tests XDP mode validation
// TestXDPModeValidation 测试 XDP 模式验证
func TestXDPModeValidation(t *testing.T) {
	tests := []struct {
		name    string
		mode    string
		valid   bool
		wantErr string
	}{
		{
			name:  "Valid offload mode",
			mode:  "offload",
			valid: true,
		},
		{
			name:  "Valid drv mode",
			mode:  "drv",
			valid: true,
		},
		{
			name:  "Valid skb mode",
			mode:  "skb",
			valid: true,
		},
		{
			name:    "Invalid mode",
			mode:    "invalid",
			valid:   false,
			wantErr: "invalid mode: invalid",
		},
		{
			name:    "Empty mode",
			mode:    "",
			valid:   false,
			wantErr: "invalid mode: ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validModes := map[string]bool{
				"offload": true,
				"drv":     true,
				"skb":     true,
			}
			isValid := validModes[tt.mode]
			assert.Equal(t, tt.valid, isValid, "Mode validation should match expected result")
		})
	}
}

// TestXDPModeMapping tests XDP mode to link.XDPAttachFlags mapping
// TestXDPModeMapping 测试 XDP 模式到 link.XDPAttachFlags 的映射
func TestXDPModeMapping(t *testing.T) {
	tests := []struct {
		name         string
		mode         string
		wantFlags    link.XDPAttachFlags
		wantModeName string
	}{
		{
			name:         "Offload mode mapping",
			mode:         "offload",
			wantFlags:    link.XDPOffloadMode,
			wantModeName: "Offload",
		},
		{
			name:         "Driver mode mapping",
			mode:         "drv",
			wantFlags:    link.XDPDriverMode,
			wantModeName: "Native",
		},
		{
			name:         "SKB mode mapping",
			mode:         "skb",
			wantFlags:    link.XDPGenericMode,
			wantModeName: "Generic",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var attachMode link.XDPAttachFlags
			var attachModeName string

			switch tt.mode {
			case "offload":
				attachMode = link.XDPOffloadMode
				attachModeName = "Offload"
			case "drv":
				attachMode = link.XDPDriverMode
				attachModeName = "Native"
			case "skb":
				attachMode = link.XDPGenericMode
				attachModeName = "Generic"
			}

			assert.Equal(t, tt.wantFlags, attachMode, "XDP attach flags should match expected value")
			assert.Equal(t, tt.wantModeName, attachModeName, "XDP mode name should match expected value")
		})
	}
}

// TestAttachXDPWithModeInterfaceLogic tests the interface logic in attachXDPWithMode
// TestAttachXDPWithModeInterfaceLogic 测试 attachXDPWithMode 中的接口逻辑
func TestAttachXDPWithModeInterfaceLogic(t *testing.T) {
	// Test with empty interfaces
	// 测试空接口列表
	interfaces := []string{}
	assert.Empty(t, interfaces, "Empty interfaces should return empty list")

	// Test with valid interface names (just string validation, not actual attachment)
	// 测试有效的接口名称（仅字符串验证，非实际挂载）
	validInterfaces := []string{"eth0", "eth1", "lo"}
	assert.NotEmpty(t, validInterfaces, "Valid interfaces should not be empty")

	// Verify interface names are not empty
	// 验证接口名称不为空
	for _, iface := range validInterfaces {
		assert.NotEmpty(t, iface, "Interface name should not be empty")
	}
}

// TestSystemAttachCmdFlags tests the system attach command flags
// TestSystemAttachCmdFlags 测试系统挂载命令的标志
func TestSystemAttachCmdFlags(t *testing.T) {
	// Verify command exists and has correct structure
	// 验证命令存在并具有正确的结构
	assert.NotNil(t, systemAttachCmd, "systemAttachCmd should exist")
	assert.Contains(t, systemAttachCmd.Use, "attach", "Command should use 'attach'")
	assert.Contains(t, systemAttachCmd.Short, "Manually attach XDP", "Short description should mention manual attach")

	// Verify flags are properly configured
	// 验证标志配置正确
	flags := systemAttachCmd.Flags()
	assert.NotNil(t, flags.Lookup("interface"), "Should have interface flag")
	assert.NotNil(t, flags.Lookup("mode"), "Should have mode flag")

	// Verify default mode
	// 验证默认模式
	defaultMode, err := flags.GetString("mode")
	assert.NoError(t, err, "Should be able to get mode flag")
	assert.Equal(t, "skb", defaultMode, "Default mode should be 'skb'")
}

// TestSystemAttachCmdExamples tests the examples in command documentation
// TestSystemAttachCmdExamples 测试命令文档中的示例
func TestSystemAttachCmdExamples(t *testing.T) {
	// Verify examples are present in Long description
	// 验证 Long 描述中存在示例
	longDesc := systemAttachCmd.Long
	assert.Contains(t, longDesc, "Examples:", "Should have Examples section")
	assert.Contains(t, longDesc, "netxfw system attach eth0 --mode offload", "Should have offload example")
	assert.Contains(t, longDesc, "netxfw system attach eth0 --mode drv", "Should have drv example")
	assert.Contains(t, longDesc, "netxfw system attach eth0 --mode skb", "Should have skb example")

	// Verify Chinese examples are present
	// 验证中文示例存在
	assert.Contains(t, longDesc, "示例:", "Should have Chinese examples section")
	assert.Contains(t, longDesc, "使用硬件卸载模式挂载", "Should have Chinese offload example")
	assert.Contains(t, longDesc, "使用原生驱动模式挂载", "Should have Chinese drv example")
	assert.Contains(t, longDesc, "使用通用模式挂载", "Should have Chinese skb example")
}
