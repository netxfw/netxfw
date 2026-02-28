package agent

import (
	"fmt"
	"os"

	"github.com/netxfw/netxfw/cmd/netxfw/commands/common"
	"github.com/netxfw/netxfw/internal/config"
	"github.com/netxfw/netxfw/internal/plugins/types"
	"github.com/netxfw/netxfw/internal/runtime"
	"github.com/netxfw/netxfw/internal/utils/logger"
	"github.com/netxfw/netxfw/internal/xdp"
	"github.com/netxfw/netxfw/pkg/sdk"
	"github.com/spf13/cobra"
)

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
		config.SetConfigPath(e.config)
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
func (e *CommandExecutor) LoadConfig() (*types.GlobalConfig, error) {
	configPath := runtime.ConfigPath
	if configPath == "" {
		configPath = config.DefaultConfigPath
	}
	return types.LoadGlobalConfig(configPath)
}

// LoadManager 加载XDP管理器
// LoadManager loads the XDP manager
func (e *CommandExecutor) LoadManager() (*xdp.Manager, error) {
	log := logger.Get(e.cmd.Context())
	return xdp.NewManagerFromPins(config.GetPinPath(), log)
}

// LoadManagerFromConfig 从配置加载XDP管理器
// LoadManagerFromConfig loads XDP manager from config
func (e *CommandExecutor) LoadManagerFromConfig(cfg *types.GlobalConfig) (*xdp.Manager, error) {
	log := logger.Get(e.cmd.Context())
	return xdp.NewManager(cfg.Capacity, log)
}

// ExecuteWithSDK 使用SDK执行命令
// ExecuteWithSDK executes command with SDK
func (e *CommandExecutor) ExecuteWithSDK(execFunc func(*sdk.SDK) error) {
	if err := e.EnsureMode().ApplyFlags().Do(func() error {
		s, err := e.GetSDK()
		if err != nil {
			return fmt.Errorf("[ERROR] Failed to get SDK: %v", err)
		}
		return execFunc(s)
	}); err != nil {
		e.cmd.PrintErrln(err)
		os.Exit(1)
	}
}

// ExecuteWithManager 使用XDP管理器执行命令
// ExecuteWithManager executes command with XDP manager
func (e *CommandExecutor) ExecuteWithManager(execFunc func(*xdp.Manager) error) {
	if err := e.EnsureMode().ApplyFlags().Do(func() error {
		manager, err := e.LoadManager()
		if err != nil {
			return fmt.Errorf("[ERROR] Failed to load XDP manager: %v", err)
		}
		defer manager.Close()
		return execFunc(manager)
	}); err != nil {
		e.cmd.PrintErrln(err)
		os.Exit(1)
	}
}

// ExecuteWithConfigManager 使用配置和XDP管理器执行命令
// ExecuteWithConfigManager executes command with config and XDP manager
func (e *CommandExecutor) ExecuteWithConfigManager(execFunc func(*types.GlobalConfig, *xdp.Manager) error) {
	if err := e.EnsureMode().ApplyFlags().Do(func() error {
		cfg, err := e.LoadConfig()
		if err != nil {
			return fmt.Errorf("[ERROR] Failed to load configuration: %v", err)
		}
		manager, err := e.LoadManager()
		if err != nil {
			return fmt.Errorf("[ERROR] Failed to load XDP manager: %v", err)
		}
		defer manager.Close()
		return execFunc(cfg, manager)
	}); err != nil {
		e.cmd.PrintErrln(err)
		os.Exit(1)
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

// Global helper functions to maintain backward compatibility
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
		cmd.PrintErrln(err)
		os.Exit(1)
	}
}

// RegisterCommonFlags 为命令注册常用标志 (-c, -i)
func RegisterCommonFlags(cmd *cobra.Command) {
	cmd.Flags().StringP("config", "c", "", "Configuration file to use")
	cmd.Flags().StringP("interface", "i", "", "Network interface to use")
}
