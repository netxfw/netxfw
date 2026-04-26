package agent

import (
	"fmt"

	"github.com/netxfw/netxfw/cmd/common"
	sdk "github.com/netxfw/netxfw/pkg/sdk"
	"github.com/spf13/cobra"
)

var lastCommandErr error

func setLastCommandError(err error) {
	lastCommandErr = err
}

// ConsumeLastCommandError returns the latest command error and clears it.
func ConsumeLastCommandError() error {
	err := lastCommandErr
	lastCommandErr = nil
	return err
}

func reportCommandError(cmd *cobra.Command, err error) {
	if err == nil {
		return
	}
	cmd.PrintErrln(err)
	setLastCommandError(err)
}

// CommandExecutor 统一的命令执行器，处理所有命令的通用逻辑
// CommandExecutor统一的命令执行器，处理所有命令的通用逻辑
type CommandExecutor struct {
	cmd    *cobra.Command
	config string
	iface  string
}

// NewCommandExecutor 创建新的命令执行器
// NewCommandExecutor creates a new command executor
func NewCommandExecutor(cmd *cobra.Command) *CommandExecutor {
	return &CommandExecutor{
		cmd: cmd,
	}
}

// WithConfig 设置配置文件路径
// WithConfig sets the config file path
func (e *CommandExecutor) WithConfig(path string) *CommandExecutor {
	e.config = path
	return e
}

// WithInterface 设置网络接口
// WithInterface sets the network interface
func (e *CommandExecutor) WithInterface(name string) *CommandExecutor {
	e.iface = name
	return e
}

// ApplyFlags 应用命令标志到配置
// ApplyFlags applies command flags to config
func (e *CommandExecutor) ApplyFlags() *CommandExecutor {
	if e.config != "" {
		commandRuntimeService.SetConfigPath(e.config)
	}
	return e
}

// EnsureMode 确保运行模式为standalone
// EnsureMode ensures the running mode is standalone
func (e *CommandExecutor) EnsureMode() *CommandExecutor {
	common.EnsureStandaloneMode()
	return e
}

// GetSDK 获取SDK实例
// GetSDK gets the SDK instance
func (e *CommandExecutor) GetSDK() (*sdk.SDK, error) {
	return common.GetSDK()
}

// LoadConfig 加载配置
// LoadConfig loads the configuration
func (e *CommandExecutor) LoadConfig() (*sdk.GlobalConfig, error) {
	return commandRuntimeService.LoadConfig()
}

// ExecuteWithSDK 使用SDK执行命令
// ExecuteWithSDK executes command with SDK
func (e *CommandExecutor) ExecuteWithSDK(execFunc func(*sdk.SDK) error) {
	if err := e.EnsureMode().ApplyFlags().Do(func() error {
		if commandRuntimeService.IsTestMode() {
			s, err := e.GetSDK()
			if err != nil {
				return fmt.Errorf("[ERROR] Failed to get SDK: %v", err)
			}
			return execFunc(s)
		}

		if !commandRuntimeService.IsXDPLoaded() {
			e.PrintWarning("XDP is not attached to any interface. Please run 'netxfw system on' or 'netxfw system load' first.")
			e.PrintWarning("XDP 未挂载到任何接口。请先运行 'netxfw system on' 或 'netxfw system load'。")
			return nil
		}

		s, err := e.GetSDK()
		if err != nil {
			return fmt.Errorf("[ERROR] Failed to get SDK: %v", err)
		}
		return execFunc(s)
	}); err != nil {
		reportCommandError(e.cmd, err)
	}
}

// ExecuteWithSDKAndConfig executes command with config and SDK.
func (e *CommandExecutor) ExecuteWithSDKAndConfig(execFunc func(*sdk.GlobalConfig, *sdk.SDK) error) {
	if err := e.EnsureMode().ApplyFlags().Do(func() error {
		if !commandRuntimeService.IsTestMode() && !commandRuntimeService.IsXDPLoaded() {
			e.PrintWarning("XDP is not attached to any interface. Please run 'netxfw system on' or 'netxfw system load' first.")
			e.PrintWarning("XDP 未挂载到任何接口。请先运行 'netxfw system on' 或 'netxfw system load'。")
			return nil
		}

		cfg, err := e.LoadConfig()
		if err != nil {
			return fmt.Errorf("[ERROR] Failed to load configuration: %v", err)
		}

		s, err := e.GetSDK()
		if err != nil {
			return fmt.Errorf("[ERROR] Failed to get SDK: %v", err)
		}
		return execFunc(cfg, s)
	}); err != nil {
		reportCommandError(e.cmd, err)
	}
}

// Do 执行核心逻辑
// Do executes the core logic
func (e *CommandExecutor) Do(f func() error) error {
	return f()
}

// PrintSuccess 打印成功消息
// PrintSuccess prints success message
func (e *CommandExecutor) PrintSuccess(msg string) {
	e.cmd.Println("[OK] " + msg)
}

// PrintError 打印错误消息
// PrintError prints error message
func (e *CommandExecutor) PrintError(msg string) {
	e.cmd.PrintErrln("[ERROR] " + msg)
}

// PrintWarning 打印警告消息
// PrintWarning prints warning message
func (e *CommandExecutor) PrintWarning(msg string) {
	e.cmd.PrintErrln("[WARN]  " + msg)
}

// Global helper functions kept for older command wiring
// 全局辅助函数以保持向后兼容性

// Execute executes a command with common setup and error handling
// Execute 使用通用设置和错误处理执行命令
func Execute(cmd *cobra.Command, args []string, execFunc func(*sdk.SDK) error) {
	executor := NewCommandExecutor(cmd)
	configFile, _ := cmd.Flags().GetString("config")

	executor.WithConfig(configFile).ExecuteWithSDK(execFunc)
}

// ExecuteWithArgs executes a command with common setup, arguments and error handling
// ExecuteWithArgs 使用通用设置、参数和错误处理执行命令
func ExecuteWithArgs(cmd *cobra.Command, args []string, execFunc func(*sdk.SDK, []string) error) {
	configFile, _ := cmd.Flags().GetString("config")
	executor := NewCommandExecutor(cmd).WithConfig(configFile)

	if err := executor.EnsureMode().ApplyFlags().Do(func() error {
		s, err := executor.GetSDK()
		if err != nil {
			return fmt.Errorf("[ERROR] Failed to get SDK: %v", err)
		}
		return execFunc(s, args)
	}); err != nil {
		reportCommandError(cmd, err)
	}
}

// RegisterCommonFlags 为命令注册常用标志 (-c, -i)
func RegisterCommonFlags(cmd *cobra.Command) {
	cmd.Flags().StringP("config", "c", "", "Configuration file to use")
	cmd.Flags().StringP("interface", "i", "", "Network interface to use")
}
