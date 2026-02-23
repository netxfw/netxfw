package fmtutil

import (
	"os"
	"os/exec"
)

// RunShellCommand executes a shell command and pipes output to stdout/stderr.
// RunShellCommand 执行 Shell 命令并将输出通过管道传输到 stdout/stderr。
func RunShellCommand(command string) error {
	cmd := exec.Command("bash", "-c", command)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
