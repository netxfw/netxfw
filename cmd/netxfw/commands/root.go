package commands

import (
	"fmt"
	"os"

	"github.com/netxfw/netxfw/cmd/netxfw/commands/agent"
	"github.com/netxfw/netxfw/internal/config"
	"github.com/netxfw/netxfw/internal/plugins/types"
	"github.com/netxfw/netxfw/internal/runtime"
	"github.com/netxfw/netxfw/internal/utils/logger"
	"github.com/spf13/cobra"
)

var RootCmd = &cobra.Command{
	Use:   "netxfw",
	Short: "A high-performance eBPF/XDP based firewall",
	// Short: 一个基于 eBPF/XDP 的高性能防火墙
	Long: `netxfw is a high-performance firewall built on eBPF/XDP technology.
It provides stateful packet filtering, connection tracking, and rate limiting.
netxfw 是一个基于 eBPF/XDP 技术构建的高性能防火墙。
它提供有状态包过滤、连接跟踪和速率限制。`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// Load configuration to get logging settings
		// 加载配置以获取日志设置
		cfgPath := runtime.ConfigPath
		if cfgPath == "" {
			cfgPath = config.DefaultConfigPath
		}

		globalCfg, err := types.LoadGlobalConfig(cfgPath)
		if err != nil {
			// If config fails to load, use default logging config (console only)
			// 如果加载配置失败，使用默认日志配置（仅控制台）
			logger.Init(logger.LoggingConfig{
				Enabled: true,
				Level:   "info",
			})
		} else {
			logger.Init(globalCfg.Logging)
		}

		// Inject logger into context
		// 将 Logger 注入 Context
		ctx := logger.WithContext(cmd.Context(), logger.Get(nil))
		cmd.SetContext(ctx)
	},
}

func init() {
	// Operation mode: dp (Data Plane) or agent (Control Plane)
	// 运行模式：dp（数据平面）或 agent（控制平面）
	RootCmd.PersistentFlags().StringVar(&runtime.Mode, "mode", "", "Operation mode: dp (Data Plane) or agent (Control Plane)")

	// Config file path
	// 配置文件路径
	RootCmd.PersistentFlags().StringVarP(&runtime.ConfigPath, "config", "c", "", fmt.Sprintf("Path to configuration file (default: %s)", config.DefaultConfigPath))

	// Register simplified core commands
	// 注册精简版核心命令
	RootCmd.AddCommand(agent.SimpleStatusCmd)
	RootCmd.AddCommand(agent.SimpleStartCmd)
	RootCmd.AddCommand(agent.SimpleStopCmd)
	RootCmd.AddCommand(agent.SimpleReloadCmd)
	RootCmd.AddCommand(agent.SimpleVersionCmd)

	// Register ufw-style command aliases
	// 注册 ufw 风格的命令别名
	RootCmd.AddCommand(agent.UfwEnableCmd)
	RootCmd.AddCommand(agent.UfwDisableCmd)
	RootCmd.AddCommand(agent.UfwDenyCmd)
	RootCmd.AddCommand(agent.UfwResetCmd)
	RootCmd.AddCommand(agent.UfwDeleteCmd)

	// Register verbose flag for status command
	// 为 status 命令注册 verbose 标志
	agent.SimpleStatusCmd.Flags().BoolP("verbose", "v", false, "Show verbose output with detailed statistics")
	// agent.SimpleStatusCmd.Flags().BoolP("verbose", "v", false, "显示详细统计信息")

	// Register XDP layer commands (recommended for blocking IPs)
	// 注册 XDP 层命令（推荐用于封禁 IP）
	RootCmd.AddCommand(agent.SimpleBlockCmd)
	RootCmd.AddCommand(agent.SimpleUnblockCmd)
	RootCmd.AddCommand(agent.SimpleListCmd)
	RootCmd.AddCommand(agent.SimpleClearCmd)
}

func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
