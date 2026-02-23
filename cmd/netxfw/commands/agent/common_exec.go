package agent

import (
	"os"

	"github.com/netxfw/netxfw/cmd/netxfw/commands/common"
	"github.com/netxfw/netxfw/internal/config"
	"github.com/netxfw/netxfw/pkg/sdk"
	"github.com/spf13/cobra"
)

// CommandExecutor provides common execution pattern for all commands
// RegisterCommonFlags 为命令注册常用标志 (-c, -i)
func RegisterCommonFlags(cmd *cobra.Command) {
	cmd.Flags().StringP("config", "c", "", "Configuration file to use")
	cmd.Flags().StringP("interface", "i", "", "Network interface to use")
}

// CommandExecutor 为所有命令提供通用执行模式
type CommandExecutor struct{}

// Execute executes a command with common setup and error handling
// Execute 使用通用设置和错误处理执行命令
func (ce *CommandExecutor) Execute(cmd *cobra.Command, args []string, execFunc func(*sdk.SDK) error) {
	ce.applyFlags(cmd)
	common.EnsureStandaloneMode()

	s, err := common.GetSDK()
	if err != nil {
		cmd.PrintErrln(err)
		os.Exit(1)
	}

	if err := execFunc(s); err != nil {
		cmd.PrintErrln(err)
		os.Exit(1)
	}
}

// applyFlags 解析并应用命令标志到配置中
func (ce *CommandExecutor) applyFlags(cmd *cobra.Command) {
	// 设置配置文件（如果提供）
	configFile, _ := cmd.Flags().GetString("config")
	if configFile != "" {
		config.SetConfigPath(configFile)
	}

	// 设置接口（如果提供）
	interfaceName, _ := cmd.Flags().GetString("interface")
	if interfaceName != "" {
		configManager := config.GetConfigManager()
		// 确保配置已加载
		if configManager.GetConfig() == nil {
			_ = configManager.LoadConfig()
		}

		currentConfig := configManager.GetConfig()
		if currentConfig != nil {
			newConfig := *currentConfig
			newConfig.Base.Interfaces = []string{interfaceName}
			configManager.UpdateConfig(&newConfig)
		}
	}
}

// ExecuteWithArgs executes a command with common setup, arguments and error handling
// ExecuteWithArgs 使用通用设置、参数和错误处理执行命令
func (ce *CommandExecutor) ExecuteWithArgs(cmd *cobra.Command, args []string, execFunc func(*sdk.SDK, []string) error) {
	ce.applyFlags(cmd)
	common.EnsureStandaloneMode()

	s, err := common.GetSDK()
	if err != nil {
		cmd.PrintErrln(err)
		os.Exit(1)
	}

	if err := execFunc(s, args); err != nil {
		cmd.PrintErrln(err)
		os.Exit(1)
	}
}

// Global CommandExecutor instance
// 全局 CommandExecutor 实例
var executor = &CommandExecutor{}

// Execute executes a command with common setup and error handling
// Execute 使用通用设置和错误处理执行命令
func Execute(cmd *cobra.Command, args []string, execFunc func(*sdk.SDK) error) {
	executor.Execute(cmd, args, execFunc)
}

// ExecuteWithArgs executes a command with common setup, arguments and error handling
// ExecuteWithArgs 使用通用设置、参数和错误处理执行命令
func ExecuteWithArgs(cmd *cobra.Command, args []string, execFunc func(*sdk.SDK, []string) error) {
	executor.ExecuteWithArgs(cmd, args, execFunc)
}
