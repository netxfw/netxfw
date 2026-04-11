package agent

import (
	"fmt"
	"strconv"
	"time"

	"github.com/netxfw/netxfw/cmd/common"
	"github.com/netxfw/netxfw/pkg/sdk"
	"github.com/spf13/cobra"
)

var SimpleStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show system status",
	Long: `Show system status including XDP program status and performance statistics
Use -v for verbose output with detailed statistics`,
	Run: func(cmd *cobra.Command, args []string) {
		configFile, _ := cmd.Flags().GetString("config")

		verbose, _ := cmd.Flags().GetBool("verbose")

		executor := NewCommandExecutor(cmd).WithConfig(configFile)

		executor.ExecuteWithSDK(func(s *sdk.SDK) error {
			w := cmd.OutOrStdout()
			if verbose {
				return showStatus(cmd.Context(), w, s)
			}

			pass, drops, err := s.Stats.GetCounters()
			if err != nil {
				fmt.Fprintf(w, "[WARN] Could not retrieve statistics: %v\n", err)
				return nil
			}

			fmt.Fprintln(w, "[OK] Firewall Status: Running")
			fmt.Fprintln(w)

			totalPackets := pass + drops
			passPercent := float64(pass) / float64(totalPackets) * 100
			fmt.Fprintf(w, "[Stats] Traffic: %s packets (Pass: %.1f%%, Drop: %.1f%%)\n",
				commandRuntimeService.FormatNumberWithComma(totalPackets), passPercent, 100-passPercent)

			trafficStats, err := commandRuntimeService.LoadTrafficStats()
			if err == nil && trafficStats.LastUpdateTime.After(time.Time{}) {
				fmt.Fprintf(w, "[Rate] Current: %s pps (%s)\n",
					commandRuntimeService.FormatNumberWithComma(trafficStats.CurrentPPS),
					commandRuntimeService.FormatBPS(trafficStats.CurrentBPS))
			}

			blacklistCount, _ := s.GetManager().GetLockedIPCount()
			dynBlacklistCount, _ := s.GetManager().GetDynLockListCount()
			totalBlocked := uint64(blacklistCount) + uint64(dynBlacklistCount)
			if totalBlocked > 0 {
				fmt.Fprintf(w, "[Block] Banned IPs: %s (Static: %s, Dynamic: %s)\n",
					commandRuntimeService.FormatNumberWithComma(totalBlocked),
					commandRuntimeService.FormatNumberWithComma(uint64(blacklistCount)),
					commandRuntimeService.FormatNumberWithComma(uint64(dynBlacklistCount)))
			} else {
				fmt.Fprintln(w, "[Block] Banned IPs: 0")
			}

			connCount, _ := s.GetManager().GetConntrackCount()
			fmt.Fprintf(w, "[Conn] Active connections: %s\n", commandRuntimeService.FormatNumberWithComma(uint64(connCount)))

			whitelistCount, _ := s.GetManager().GetWhitelistCount()
			if whitelistCount > 0 {
				fmt.Fprintf(w, "[Allow] Whitelisted IPs: %s\n", commandRuntimeService.FormatNumberWithComma(uint64(whitelistCount)))
			}

			showCompactMapStatistics(w, s.GetManager())
			showTopBlockedIPs(w, s.Stats, drops)

			fmt.Fprintln(w)
			fmt.Fprintln(w, "[Tip] Use 'netxfw status -v' for detailed info")
			return nil
		})
	},
}

var SimpleStartCmd = &cobra.Command{
	Use:    "start",
	Short:  "Start netxfw firewall",
	Hidden: true,
	Long:   `Start netxfw firewall (load XDP driver and start agent)`,
	Run: func(cmd *cobra.Command, args []string) {
		configFile, _ := cmd.Flags().GetString("config")
		executor := NewCommandExecutor(cmd).WithConfig(configFile)

		executor.Do(func() error {
			if err := systemService.InstallXDP(cmd.Context(), nil); err != nil {
				return fmt.Errorf("[ERROR] Failed to start XDP program: %w", err)
			}

			if commandRuntimeService.GetRuntimeMode() == "agent" || commandRuntimeService.GetRuntimeMode() == "" {
				fmt.Println("[RELOAD] Starting agent...")
			}

			executor.PrintSuccess("netxfw started successfully")
			return nil
		})
	},
}

var SimpleStopCmd = &cobra.Command{
	Use:    "stop",
	Short:  "Stop netxfw firewall",
	Hidden: true,
	Long:   `Stop netxfw firewall (unload XDP driver and stop agent)`,
	Run: func(cmd *cobra.Command, args []string) {
		configFile, _ := cmd.Flags().GetString("config")
		executor := NewCommandExecutor(cmd).WithConfig(configFile)

		executor.Do(func() error {
			if commandRuntimeService.GetRuntimeMode() == "agent" || commandRuntimeService.GetRuntimeMode() == "" {
				fmt.Println("[RELOAD] Stopping agent...")
			}

			if err := systemService.RemoveXDP(cmd.Context(), nil); err != nil {
				return fmt.Errorf("[ERROR] Failed to stop XDP program: %w", err)
			}

			executor.PrintSuccess("netxfw stopped successfully")
			return nil
		})
	},
}

var SimpleReloadCmd = &cobra.Command{
	Use:   "reload",
	Short: "Reload configuration and sync to BPF maps",
	Long: `Reload configuration and sync to BPF maps: reads configuration from files and updates BPF maps without reloading XDP program.
This is faster than full reload and maintains existing connections.`,
	Run: func(cmd *cobra.Command, args []string) {
		configFile, _ := cmd.Flags().GetString("config")
		executor := NewCommandExecutor(cmd).WithConfig(configFile)

		executor.ExecuteWithSDK(func(s *sdk.SDK) error {
			if err := commandRuntimeService.LoadAndSyncConfigToRuntime(s); err != nil {
				return fmt.Errorf("[ERROR] Failed to sync configuration to BPF maps: %v", err)
			}
			executor.PrintSuccess("Configuration reloaded and synced to BPF maps successfully")
			return nil
		})
	},
}

var SimpleUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update netxfw software",
	Long:  `Check for the latest version on GitHub and install it`,
	Run: func(cmd *cobra.Command, args []string) {
		configFile, _ := cmd.Flags().GetString("config")
		executor := NewCommandExecutor(cmd).WithConfig(configFile)

		executor.Do(func() error {
			fmt.Println("[START] Checking for updates...")
			if err := commandRuntimeService.RunDeployUpdate(); err != nil {
				return fmt.Errorf("[ERROR] Update failed: %v", err)
			}
			return nil
		})
	},
}

var SimpleVersionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version information",
	Long:  `Show version information`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("netxfw version %s\n", commandRuntimeService.Version())
	},
}

var SimplePluginCmd = &cobra.Command{
	Use:   "plugin",
	Short: "Manage BPF plugins",
	Long: `Manage BPF plugins for extending firewall functionality.

BPF plugins allow you to extend the firewall with custom packet processing logic.
Plugins are loaded into the jump table at specific indices (2-15).

Subcommands:
  plugin load <path> <index>   Load a BPF plugin from ELF file
  plugin remove <index>        Remove a plugin from the jump table
  plugin list                  List loaded plugins

Examples:
  netxfw plugin load /etc/netxfw/plugins/custom_filter.o 2
  netxfw plugin remove 2
  netxfw plugin list`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

var pluginLoadCmd = &cobra.Command{
	Use:   "load <path> <index>",
	Short: "Load a BPF plugin",
	Long: `Load a BPF plugin from an ELF file into the jump table.

The index must be between 2 and 15 (inclusive).
Plugin ELF files must contain a valid XDP program.`,
	Args: cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		path := args[0]
		index, err := strconv.Atoi(args[1])
		if err != nil {
			reportCommandError(cmd, fmt.Errorf("[ERROR] Invalid index: must be a number"))
			return
		}

		configFile, _ := cmd.Flags().GetString("config")
		executor := NewCommandExecutor(cmd).WithConfig(configFile)

		executor.Do(func() error {
			if err := commandRuntimeService.LoadPlugin(cmd.Context(), path, index); err != nil {
				return fmt.Errorf("[ERROR] Failed to load plugin: %v", err)
			}
			executor.PrintSuccess(fmt.Sprintf("Plugin loaded: %s at index %d", path, index))
			return nil
		})
	},
}

var pluginRemoveCmd = &cobra.Command{
	Use:   "remove <index>",
	Short: "Remove a BPF plugin",
	Long:  `Remove a BPF plugin from the jump table by index.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		index, err := strconv.Atoi(args[0])
		if err != nil {
			reportCommandError(cmd, fmt.Errorf("[ERROR] Invalid index: must be a number"))
			return
		}

		configFile, _ := cmd.Flags().GetString("config")
		executor := NewCommandExecutor(cmd).WithConfig(configFile)

		executor.Do(func() error {
			if err := commandRuntimeService.RemovePlugin(cmd.Context(), index); err != nil {
				return fmt.Errorf("[ERROR] Failed to remove plugin: %v", err)
			}
			executor.PrintSuccess(fmt.Sprintf("Plugin removed from index %d", index))
			return nil
		})
	},
}

var pluginListCmd = &cobra.Command{
	Use:   "list",
	Short: "List loaded BPF plugins",
	Long:  `List all currently loaded BPF plugins and their indices.`,
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		configFile, _ := cmd.Flags().GetString("config")
		executor := NewCommandExecutor(cmd).WithConfig(configFile)

		executor.Do(func() error {
			fmt.Println("=== BPF Plugins ===")
			fmt.Println("Index Range: 2-14")
			fmt.Println()

			slots, err := commandRuntimeService.ListLoadedPlugins(cmd.Context())
			if err != nil {
				return fmt.Errorf("[ERROR] Failed to list plugins: %v", err)
			}
			if len(slots) == 0 {
				fmt.Println("  No plugins loaded")
				return nil
			}
			for _, slot := range slots {
				fmt.Printf("  [%d] Plugin loaded (ID: %d)\n", slot.Index, slot.Program)
			}
			return nil
		})
	},
}

var SimpleWebCmd = &cobra.Command{
	Use:   "web",
	Short: "Show web interface information",
	Long:  `Show web interface information`,
	Run: func(cmd *cobra.Command, args []string) {
		configFile, _ := cmd.Flags().GetString("config")
		executor := NewCommandExecutor(cmd).WithConfig(configFile)

		executor.Do(func() error {
			fmt.Println("[Web] Interface: http://localhost:8080")
			return nil
		})
	},
}

var SimpleInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize configuration",
	Long:  `Initialize configuration file`,
	Run: func(cmd *cobra.Command, args []string) {
		configFile, _ := cmd.Flags().GetString("config")
		executor := NewCommandExecutor(cmd).WithConfig(configFile)

		executor.Do(func() error {
			systemService.InitConfiguration(cmd.Context())
			executor.PrintSuccess("Configuration initialized")
			return nil
		})
	},
}

var SimpleTestCmd = &cobra.Command{
	Use:   "test",
	Short: "Test configuration",
	Long:  `Test configuration file`,
	Run: func(cmd *cobra.Command, args []string) {
		configFile, _ := cmd.Flags().GetString("config")
		executor := NewCommandExecutor(cmd).WithConfig(configFile)

		executor.Do(func() error {
			systemService.TestConfiguration(cmd.Context())
			executor.PrintSuccess("Configuration test passed")
			return nil
		})
	},
}

var SimpleClearCmd = &cobra.Command{
	Use:   "clear",
	Short: "Clear all blocked IPs",
	Long: `Clear all blocked IPs at XDP layer.

默认清空静态黑名单（永久封禁的 IP）。
使用 --dynamic 标志清空动态黑名单（临时封禁的 IP）。
使用 --force 标志跳过确认提示。

Examples:
  netxfw clear              # 清空静态黑名单
  netxfw clear --dynamic    # 清空动态黑名单
  netxfw clear --force      # 清空静态黑名单（跳过确认）`,
	Run: func(cmd *cobra.Command, args []string) {
		configFile, _ := cmd.Flags().GetString("config")
		clearDynamic, _ := cmd.Flags().GetBool("dynamic")
		force, _ := cmd.Flags().GetBool("force")

		if !force {
			if clearDynamic {
				fmt.Println("[WARNING] This will clear all IPs from dynamic blacklist!")
			} else {
				fmt.Println("[WARNING] This will clear all IPs from static blacklist!")
			}

			if !common.AskConfirmation("Are you sure you want to continue?") {
				fmt.Println("[CANCELLED] Clear cancelled")
				return
			}
		}

		executor := NewCommandExecutor(cmd).WithConfig(configFile)

		executor.Do(func() error {
			if err := commandRuntimeService.ClearBlacklist(cmd.Context(), clearDynamic); err != nil {
				if clearDynamic {
					return fmt.Errorf("[ERROR] Failed to clear dynamic blacklist: %v", err)
				}
				return fmt.Errorf("[ERROR] Failed to clear static blacklist: %v", err)
			}
			if clearDynamic {
				executor.PrintSuccess("Dynamic blacklist cleared successfully")
			} else {
				executor.PrintSuccess("Static blacklist cleared successfully")
			}
			return nil
		})
	},
}

var SimpleRuleCmd = &cobra.Command{
	Use:   "rule",
	Short: "Rule management commands",
}

var UfwEnableCmd = &cobra.Command{
	Use:   "enable",
	Short: "Enable/start firewall",
	Long: `Enable and start the firewall.
启用并启动防火墙。`,
	Run: func(cmd *cobra.Command, args []string) {
		SimpleStartCmd.Run(cmd, args)
	},
}

var UfwDisableCmd = &cobra.Command{
	Use:   "disable",
	Short: "Disable/stop firewall",
	Long: `Disable and stop the firewall.
禁用并停止防火墙。`,
	Run: func(cmd *cobra.Command, args []string) {
		SimpleStopCmd.Run(cmd, args)
	},
}

var UfwResetCmd = &cobra.Command{
	Use:   "reset",
	Short: "Reset firewall to default state",
	Long: `Reset firewall to default state (clear all rules and reload).
重置防火墙到默认状态（清除所有规则并重新加载）。`,
	Run: func(cmd *cobra.Command, args []string) {
		configFile, _ := cmd.Flags().GetString("config")
		executor := NewCommandExecutor(cmd).WithConfig(configFile)

		executor.ExecuteWithSDK(func(s *sdk.SDK) error {
			result := commandRuntimeService.ResetFirewall(s)
			fmt.Println("[RESET] Clearing all firewall rules...")
			for _, warning := range result.Warnings {
				cmd.PrintErrln("[WARN]", warning)
			}
			fmt.Printf("[OK] SSH port %d preserved in whitelist\n", result.SSHPort)
			fmt.Println()
			fmt.Println("[OK] Firewall has been reset successfully")
			return nil
		})
	},
}

func init() {
	RegisterCommonFlags(SimpleStatusCmd)
	RegisterCommonFlags(SimpleStartCmd)
	RegisterCommonFlags(SimpleStopCmd)
	RegisterCommonFlags(SimpleReloadCmd)
	RegisterCommonFlags(SimpleUpdateCmd)
	RegisterCommonFlags(SimpleVersionCmd)
	RegisterCommonFlags(SimpleWebCmd)
	RegisterCommonFlags(SimpleInitCmd)
	RegisterCommonFlags(SimpleTestCmd)
	RegisterCommonFlags(SimpleClearCmd)
	RegisterCommonFlags(SimpleRuleCmd)
	RegisterCommonFlags(UfwEnableCmd)
	RegisterCommonFlags(UfwDisableCmd)
	RegisterCommonFlags(UfwResetCmd)

	RegisterCommonFlags(SimplePluginCmd)
	RegisterCommonFlags(pluginLoadCmd)
	RegisterCommonFlags(pluginRemoveCmd)
	RegisterCommonFlags(pluginListCmd)
	SimplePluginCmd.AddCommand(pluginLoadCmd)
	SimplePluginCmd.AddCommand(pluginRemoveCmd)
	SimplePluginCmd.AddCommand(pluginListCmd)

	SimpleClearCmd.Flags().Bool("dynamic", false, "Clear dynamic blacklist instead of static")
	SimpleClearCmd.Flags().Bool("force", false, "Skip confirmation prompt")
}
