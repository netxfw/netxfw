package i18n

import (
	"fmt"
	"testing"
)

func TestErrorMessages(t *testing.T) {
	tests := []struct {
		name     string
		message  string
		contains []string
	}{
		{
			name:     "ErrInvalidIP",
			message:  ErrInvalidIP,
			contains: []string{"invalid IP address", "无效的 IP 地址"},
		},
		{
			name:     "ErrInvalidCIDR",
			message:  ErrInvalidCIDR,
			contains: []string{"invalid CIDR notation", "无效的 CIDR 表示法"},
		},
		{
			name:     "ErrInvalidPort",
			message:  ErrInvalidPort,
			contains: []string{"invalid port number", "无效的端口号"},
		},
		{
			name:     "ErrTimeout",
			message:  ErrTimeout,
			contains: []string{"operation timeout", "操作超时"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, expected := range tt.contains {
				if !containsString(tt.message, expected) {
					t.Errorf("message %q should contain %q", tt.message, expected)
				}
			}
		})
	}
}

func TestInfoMessages(t *testing.T) {
	tests := []struct {
		name     string
		message  string
		contains []string
	}{
		{
			name:     "InfoServiceStarted",
			message:  InfoServiceStarted,
			contains: []string{"service started", "服务已启动"},
		},
		{
			name:     "InfoIPBlocked",
			message:  InfoIPBlocked,
			contains: []string{"IP blocked", "IP 已在 XDP 层封禁"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, expected := range tt.contains {
				if !containsString(tt.message, expected) {
					t.Errorf("message %q should contain %q", tt.message, expected)
				}
			}
		})
	}
}

func TestWarnMessages(t *testing.T) {
	tests := []struct {
		name     string
		message  string
		contains []string
	}{
		{
			name:     "WarnDeprecated",
			message:  WarnDeprecated,
			contains: []string{"deprecated command", "旧命令"},
		},
		{
			name:     "WarnConfigChanged",
			message:  WarnConfigChanged,
			contains: []string{"configuration changed", "配置已更改"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, expected := range tt.contains {
				if !containsString(tt.message, expected) {
					t.Errorf("message %q should contain %q", tt.message, expected)
				}
			}
		})
	}
}

func TestHelpMessages(t *testing.T) {
	tests := []struct {
		name     string
		message  string
		contains []string
	}{
		{
			name:     "HelpIPFormat",
			message:  HelpIPFormat,
			contains: []string{"must be <ip>[:port]", "必须是 <ip>[:port]"},
		},
		{
			name:     "HelpIPv6Format",
			message:  HelpIPv6Format,
			contains: []string{"IPv6 address must be wrapped", "IPv6 地址必须使用方括号"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, expected := range tt.contains {
				if !containsString(tt.message, expected) {
					t.Errorf("message %q should contain %q", tt.message, expected)
				}
			}
		})
	}
}

func TestFormatError(t *testing.T) {
	tests := []struct {
		name     string
		msg      string
		args     []interface{}
		expected string
	}{
		{
			name:     "no args",
			msg:      ErrInvalidIP,
			args:     nil,
			expected: ErrInvalidIP,
		},
		{
			name:     "with string arg",
			msg:      ErrInvalidIP,
			args:     []interface{}{"192.168.1.1"},
			expected: ErrInvalidIP + ": 192.168.1.1",
		},
		{
			name:     "with int arg",
			msg:      ErrInvalidPort,
			args:     []interface{}{8080},
			expected: ErrInvalidPort + ": 8080",
		},
		{
			name:     "with multiple args",
			msg:      ErrInvalidIP,
			args:     []interface{}{"192.168.1.1", 8080},
			expected: ErrInvalidIP + ": 192.168.1.1, 8080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatError(tt.msg, tt.args...)
			if result != tt.expected {
				t.Errorf("FormatError() = %q, expected %q", result, tt.expected)
			}
		})
	}
}

func TestFormatArg(t *testing.T) {
	tests := []struct {
		name     string
		arg      interface{}
		expected string
	}{
		{"string", "test", "test"},
		{"int", int(42), "42"},
		{"int64", int64(123456789), "123456789"},
		{"uint", uint(100), "100"},
		{"uint64", uint64(999999999), "999999999"},
		{"float", 3.14, "3.14"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatArg(tt.arg)
			if result != tt.expected {
				t.Errorf("formatArg(%v) = %q, expected %q", tt.arg, result, tt.expected)
			}
		})
	}
}

func TestMessageUsage(t *testing.T) {
	err := fmt.Errorf("%s: %s", ErrInvalidIP, "192.168.1.1")
	if !containsString(err.Error(), "invalid IP address") {
		t.Errorf("error should contain English message")
	}
	if !containsString(err.Error(), "无效的 IP 地址") {
		t.Errorf("error should contain Chinese message")
	}
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsStringHelper(s, substr))
}

func containsStringHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
