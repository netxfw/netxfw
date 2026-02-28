package commands

import (
	"fmt"
	"os"

	"github.com/netxfw/netxfw/cmd/netxfw/commands/agent"
	"github.com/netxfw/netxfw/cmd/netxfw/commands/dp"
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
	RootCmd.AddCommand(agent.SimpleInitCmd) // init - 初始化配置
	RootCmd.AddCommand(agent.SimpleTestCmd) // test - 测试配置

	// Register ufw-style commands (enable/disable/reset)
	// 注册 ufw 风格命令（启用/禁用/重置）
	RootCmd.AddCommand(agent.UfwEnableCmd)
	RootCmd.AddCommand(agent.UfwDisableCmd)
	RootCmd.AddCommand(agent.UfwResetCmd)

	// Register verbose flag for status command
	// 为 status 命令注册 verbose 标志
	agent.SimpleStatusCmd.Flags().BoolP("verbose", "v", false, "Show verbose output with detailed statistics")

	// Register simplified firewall commands
	// 注册精简版防火墙命令
	RootCmd.AddCommand(agent.SimpleAllowCmd) // allow - 允许 IP（白名单）
	RootCmd.AddCommand(agent.SimpleDenyCmd)  // deny - 拒绝 IP（黑名单，支持 --ttl）

	// Add 'del' alias for delete command (del is primary, delete is alias)
	// 为 delete 命令添加 'del' 别名（del 为主命令，delete 为别名）
	delCmd := *agent.SimpleDeleteCmd
	delCmd.Use = "del <ip>[:port]"
	delCmd.Aliases = []string{"delete"}
	RootCmd.AddCommand(&delCmd)

	RootCmd.AddCommand(agent.SimpleListCmd)  // list - 列出所有规则
	RootCmd.AddCommand(agent.SimpleClearCmd) // clear - 清空黑名单

	// Register rule management commands
	// 注册规则管理命令
	RootCmd.AddCommand(agent.RuleCmd)

	// Register dynamic blacklist management commands
	// 注册动态黑名单管理命令
	RootCmd.AddCommand(agent.DynamicCmd)

	// Register limit/security/port/perf management commands
	// 注册限速/安全/端口/性能管理命令
	RootCmd.AddCommand(agent.LimitCmd)    // limit - 限速管理
	RootCmd.AddCommand(agent.SecurityCmd) // security - 安全策略管理
	RootCmd.AddCommand(agent.PortCmd)     // port - 端口管理
	RootCmd.AddCommand(agent.PerfCmd)     // perf - 性能监控

	// Register web and conntrack commands
	// 注册 web 和 conntrack 命令
	RootCmd.AddCommand(agent.SimpleWebCmd) // web - 显示 Web 界面信息
	RootCmd.AddCommand(dp.ConntrackCmd)    // conntrack - 显示连接跟踪表

	// Register system management commands
	// 注册系统管理命令
	RootCmd.AddCommand(agent.SystemCmd) // system - 系统管理（load/unload/reload/status/sync 等）

	// Disable powershell completion (Linux-focused project doesn't need it)
	// 禁用 powershell 补全（Linux 项目不需要）
	RootCmd.CompletionOptions.DisableDescriptions = true
}

// createCustomCompletionCmd creates a custom completion command without powershell.
// createCustomCompletionCmd 创建不含 powershell 的自定义补全命令。
func createCustomCompletionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "completion [bash|zsh|fish]",
		Short: "Generate shell autocompletion script",
		Long: `Generate shell autocompletion script for netxfw.
生成 netxfw 的 shell 自动补全脚本。

Supported shells:
  bash - Generate for bash
  zsh  - Generate for zsh
  fish - Generate for fish

Examples:
  netxfw completion bash > /etc/bash_completion.d/netxfw
  netxfw completion zsh  > "${fpath[1]}/_netxfw"
  netxfw completion fish > ~/.config/fish/completions/netxfw.fish`,
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			shell := args[0]
			switch shell {
			case "bash":
				if err := RootCmd.GenBashCompletionV2(os.Stdout, true); err != nil {
					fmt.Fprintf(os.Stderr, "Error: %v\n", err)
					os.Exit(1)
				}
			case "zsh":
				if err := RootCmd.GenZshCompletion(os.Stdout); err != nil {
					fmt.Fprintf(os.Stderr, "Error: %v\n", err)
					os.Exit(1)
				}
			case "fish":
				if err := RootCmd.GenFishCompletion(os.Stdout, true); err != nil {
					fmt.Fprintf(os.Stderr, "Error: %v\n", err)
					os.Exit(1)
				}
			default:
				fmt.Fprintf(os.Stderr, "Error: Unsupported shell: %s\nSupported: bash, zsh, fish\n", shell)
				os.Exit(1)
			}
		},
	}
}

func Execute() {
	// Replace default completion command with custom one (no powershell)
	// 用自定义补全命令替换默认命令（不含 powershell）
	var found bool
	for _, cmd := range RootCmd.Commands() {
		if cmd.Use == "completion" {
			RootCmd.RemoveCommand(cmd)
			found = true
			break
		}
	}
	if found {
		RootCmd.AddCommand(createCustomCompletionCmd())
	} else {
		// Cobra adds completion lazily, so we need to add it ourselves
		// Cobra 延迟添加 completion，所以我们需要自己添加
		RootCmd.AddCommand(createCustomCompletionCmd())
	}

	if err := RootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
