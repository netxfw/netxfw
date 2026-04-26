package agent

import (
	"fmt"

	sdk "github.com/netxfw/netxfw/pkg/sdk"
	"github.com/spf13/cobra"
)

var interfaces []string

var xdpMode string

var systemLoadCmd = &cobra.Command{
	Use:   "load",
	Short: "Load XDP driver",
	Long:  `Load XDP driver`,
	Run: func(cmd *cobra.Command, args []string) {
		configFile, _ := cmd.Flags().GetString("config")
		executor := NewCommandExecutor(cmd).WithConfig(configFile)

		if err := executor.EnsureMode().ApplyFlags().Do(func() error {
			return systemService.InstallXDP(cmd.Context(), interfaces)
		}); err != nil {
			reportCommandError(cmd, err)
		}
	},
}

var systemAttachCmd = &cobra.Command{
	Use:   "attach [interface...]",
	Short: "Manually attach XDP with specific mode",
	Long: `Manually attach XDP program to interfaces with specific mode.

Supported modes:
  - offload: Hardware offload mode (best performance, requires NIC support)
  - drv: Native driver mode (good performance, requires driver support)
  - skb: Generic/SKB mode (software fallback, works on all interfaces)

Examples:
  netxfw system attach eth0 --mode offload    # Attach with hardware offload
  netxfw system attach eth0 --mode drv        # Attach with native driver mode
  netxfw system attach eth0 --mode skb        # Attach with generic mode
  netxfw system attach eth0 eth1 --mode drv   # Attach multiple interfaces

手动挂载 XDP 程序到指定接口并选择模式。

支持的模式:
  - offload: 硬件卸载模式 (最佳性能，需要网卡支持)
  - drv: 原生驱动模式 (良好性能，需要驱动支持)
  - skb: 通用/SKB 模式 (软件回退，适用于所有接口)

示例:
  netxfw system attach eth0 --mode offload    # 使用硬件卸载模式挂载
  netxfw system attach eth0 --mode drv        # 使用原生驱动模式挂载
  netxfw system attach eth0 --mode skb        # 使用通用模式挂载
  netxfw system attach eth0 eth1 --mode drv   # 挂载多个接口`,
	Run: func(cmd *cobra.Command, args []string) {
		configFile, _ := cmd.Flags().GetString("config")
		executor := NewCommandExecutor(cmd).WithConfig(configFile)

		if err := executor.EnsureMode().ApplyFlags().Do(func() error {
			ifaceList := interfaces
			if len(args) > 0 {
				ifaceList = args
			}

			attached, err := systemService.AttachXDPWithMode(cmd.Context(), ifaceList, xdpMode)
			if err != nil {
				return fmt.Errorf("[ERROR] Failed to attach XDP: %w", err)
			}

			fmt.Printf("[OK] XDP attached successfully on %v with mode: %s\n", attached, xdpMode)
			return nil
		}); err != nil {
			reportCommandError(cmd, err)
		}
	},
}

var systemUnloadCmd = &cobra.Command{
	Use:   "unload",
	Short: "Unload XDP driver",
	Long:  `Unload XDP driver`,
	Run: func(cmd *cobra.Command, args []string) {
		configFile, _ := cmd.Flags().GetString("config")
		executor := NewCommandExecutor(cmd).WithConfig(configFile)

		if err := executor.EnsureMode().ApplyFlags().Do(func() error {
			return systemService.RemoveXDP(cmd.Context(), interfaces)
		}); err != nil {
			reportCommandError(cmd, err)
		}
	},
}

var systemReloadCmd = &cobra.Command{
	Use:   "reload",
	Short: "Reload configuration and sync to BPF maps",
	Long: `Reload configuration and sync to BPF maps: reads configuration from files and updates BPF maps without reloading XDP program.
This is faster than full reload and maintains existing connections.`,
	Run: func(cmd *cobra.Command, args []string) {
		configFile, _ := cmd.Flags().GetString("config")
		executor := NewCommandExecutor(cmd).WithConfig(configFile)

		if err := executor.EnsureMode().ApplyFlags().Do(func() error {
			if err := systemService.ReloadPinnedMaps(cmd.Context()); err != nil {
				return fmt.Errorf("[ERROR] Failed to reload configuration: %w", err)
			}

			fmt.Println("[OK] Configuration reloaded and synced to BPF maps successfully")
			return nil
		}); err != nil {
			reportCommandError(cmd, err)
		}
	},
}

var systemOnCmd = &cobra.Command{
	Use:   "on [interface...]",
	Short: "Load XDP driver (alias for 'load')",
	Long: `Load XDP driver. This is an alias for 'system load'.

Examples:
  netxfw system on
  netxfw system on eth0
  netxfw system on eth0 eth1`,
	Run: func(cmd *cobra.Command, args []string) {
		configFile, _ := cmd.Flags().GetString("config")
		executor := NewCommandExecutor(cmd).WithConfig(configFile)

		if err := executor.EnsureMode().ApplyFlags().Do(func() error {
			ifaceList := interfaces
			if len(args) > 0 {
				ifaceList = args
			}
			return systemService.InstallXDP(cmd.Context(), ifaceList)
		}); err != nil {
			reportCommandError(cmd, err)
		}
	},
}

var systemOffCmd = &cobra.Command{
	Use:   "off [interface...]",
	Short: "Unload XDP driver (alias for 'unload')",
	Long: `Unload XDP driver. This is an alias for 'system unload'.

Examples:
  netxfw system off
  netxfw system off eth0
  netxfw system off eth0 eth1`,
	Run: func(cmd *cobra.Command, args []string) {
		configFile, _ := cmd.Flags().GetString("config")
		executor := NewCommandExecutor(cmd).WithConfig(configFile)

		if err := executor.EnsureMode().ApplyFlags().Do(func() error {
			ifaceList := interfaces
			if len(args) > 0 {
				ifaceList = args
			}
			return systemService.RemoveXDP(cmd.Context(), ifaceList)
		}); err != nil {
			reportCommandError(cmd, err)
		}
	},
}

var syncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Sync configuration between files and runtime BPF maps",
	Long:  `Sync configuration between files and runtime BPF maps.`,
}

var syncToConfigCmd = &cobra.Command{
	Use:   "to-config",
	Short: "Dump runtime BPF maps to configuration files",
	Long:  `Dump runtime BPF maps to configuration files (config.toml and rules.deny.txt).`,
	Run: func(cmd *cobra.Command, args []string) {
		Execute(cmd, args, func(s *sdk.SDK) error {
			return systemService.SyncRuntimeToConfig(s)
		})
	},
}

var syncToMapCmd = &cobra.Command{
	Use:   "to-map",
	Short: "Apply configuration files to runtime BPF maps",
	Long: `Apply configuration files (config.toml and rules.deny.txt) to runtime BPF maps.
This will overwrite the runtime state with what is defined in the configuration files.`,
	Run: func(cmd *cobra.Command, args []string) {
		Execute(cmd, args, func(s *sdk.SDK) error {
			return systemService.SyncConfigToRuntimeOverwrite(s)
		})
	},
}
