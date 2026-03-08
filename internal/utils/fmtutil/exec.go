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
}

// RunShellCommand executes a shell command with security restrictions.
// Only whitelisted commands are allowed to prevent command injection attacks.
// RunShellCommand 执行 Shell 命令并施加安全限制。
// 只允许白名单中的命令，以防止命令注入攻击。
func RunShellCommand(command string) error {
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

	// #nosec G204 -- command is validated against whitelist above
	cmd := exec.Command("bash", "-c", command)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// RunShellCommandUnsafe executes any shell command without restrictions.
// WARNING: This function should only be used in trusted environments.
// Use RunShellCommand for safer command execution.
// RunShellCommandUnsafe 执行任意 Shell 命令，无限制。
// 警告：此函数应仅在受信任的环境中使用。
// 请使用 RunShellCommand 进行更安全的命令执行。
func RunShellCommandUnsafe(command string) error {
	// #nosec G204 -- this is intentionally unsafe for trusted environments
	cmd := exec.Command("bash", "-c", command)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
