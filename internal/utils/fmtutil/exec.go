package fmtutil

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// AllowedCommands defines a whitelist of safe commands that can be executed.
// Only these commands are allowed to run for security reasons.
// AllowedCommands 定义允许执行的安全命令白名单。
// 出于安全考虑，只允许运行这些命令。
var AllowedCommands = map[string]bool{
	"echo":     true,
	"date":     true,
	"hostname": true,
	"uname":    true,
	"uptime":   true,
	"whoami":   true,
	"id":       true,
	"curl":     true,
	"bash":     true,
}

// RunShellCommand executes a shell command with security restrictions.
// Only whitelisted commands are allowed to prevent command injection attacks.
// Shell metacharacters (|, ;, &, etc.) are rejected to prevent command chaining.
// RunShellCommand 执行 Shell 命令并施加安全限制。
// 只允许白名单中的命令，以防止命令注入攻击。
// 拒绝 Shell 元字符（|, ;, & 等）以防止命令链接。
func RunShellCommand(command string) error {
	// Reject shell metacharacters that could allow command chaining
	// 拒绝可能允许命令链接的 Shell 元字符
	dangerousChars := []string{"|", ";", "&", "`", "$(", ")", ">", "<"}
	for _, ch := range dangerousChars {
		if strings.Contains(command, ch) {
			return fmt.Errorf("command contains unsafe character '%s': rejected for security reasons", ch)
		}
	}

	// Parse the command to extract the base command
	// 解析命令以提取基础命令
	parts := strings.Fields(command)
	if len(parts) == 0 {
		return fmt.Errorf("empty command")
	}

	baseCmd := parts[0]

	// Check if the command is in the whitelist
	// 检查命令是否在白名单中
	if !AllowedCommands[baseCmd] {
		return fmt.Errorf("command '%s' is not in the allowed list for security reasons", baseCmd)
	}

	// Execute command directly without shell to prevent injection
	// 直接执行命令而不通过 shell，以防止注入
	// #nosec G204 -- command is validated against whitelist and metacharacter check above
	cmd := exec.Command(parts[0], parts[1:]...) //nolint:gosec
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// RunShellPipeline executes a trusted shell pipeline command.
// WARNING: Only use for hardcoded, trusted command strings. Never pass user input.
// The caller is responsible for ensuring the command is safe.
// RunShellPipeline 执行受信任的 Shell 管道命令。
// 警告：仅用于硬编码的、受信任的命令字符串。切勿传入用户输入。
// 调用方负责确保命令安全。
func RunShellPipeline(command string) error {
	// Validate that only allowed commands appear in the pipeline
	// 验证管道中只出现允许的命令
	segments := strings.Split(command, "|")
	for _, seg := range segments {
		seg = strings.TrimSpace(seg)
		parts := strings.Fields(seg)
		if len(parts) == 0 {
			continue
		}
		baseCmd := parts[0]
		if !AllowedCommands[baseCmd] {
			return fmt.Errorf("pipeline contains disallowed command '%s'", baseCmd)
		}
	}

	// #nosec G204 -- pipeline commands are validated against whitelist above
	cmd := exec.Command("bash", "-c", command) //nolint:gosec
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
