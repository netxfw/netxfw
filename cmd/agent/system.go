package agent

import (
	"fmt"

	"github.com/netxfw/netxfw/cmd/common"
	"github.com/netxfw/netxfw/internal/application/services"
	"github.com/netxfw/netxfw/pkg/sdk"
	"github.com/spf13/cobra"
)

// Drop reason codes / 丢弃原因码
const (
	DropReasonUnknown    = 0
	DropReasonInvalid    = 1
	DropReasonProtocol   = 2
	DropReasonBlacklist  = 3
	DropReasonRatelimit  = 4
	DropReasonStrictTCP  = 5
	DropReasonDefault    = 6
	DropReasonLandAttack = 7
	DropReasonBogon      = 8
	DropReasonFragment   = 9
	DropReasonBadHeader  = 10
	DropReasonTCPFlags   = 11
	DropReasonSpoof      = 12
)

// Pass reason codes / 通过原因码
const (
	PassReasonUnknown   = 100
	PassReasonWhitelist = 101
	PassReasonReturn    = 102
	PassReasonConntrack = 103
	PassReasonDefault   = 104
)

// dropReasonToString maps drop reason codes to human-readable strings
// dropReasonToString 将丢弃原因码映射为可读字符串
func dropReasonToString(reason uint32) string {
	switch reason {
	case DropReasonBlacklist:
		return "BLACKLIST"
	case DropReasonRatelimit:
		return "RATELIMIT"
	case DropReasonDefault:
		return "DEFAULT_DENY"
	case DropReasonInvalid:
		return "INVALID"
	case DropReasonProtocol:
		return "PROTOCOL"
	case DropReasonStrictTCP:
		return "STRICT_TCP"
	case DropReasonLandAttack:
		return "LAND_ATTACK"
	case DropReasonBogon:
		return "BOGON"
	case DropReasonFragment:
		return "FRAGMENT"
	case DropReasonBadHeader:
		return "BAD_HEADER"
	case DropReasonTCPFlags:
		return "TCP_FLAGS"
	case DropReasonSpoof:
		return "SPOOF"
	default:
		return "UNKNOWN"
	}
}

// passReasonToString maps pass reason codes to human-readable strings
// passReasonToString 将通过原因码映射为可读字符串
func passReasonToString(reason uint32) string {
	switch reason {
	case PassReasonWhitelist:
		return "WHITELIST"
	case PassReasonReturn:
		return "RETURN"
	case PassReasonConntrack:
		return "CONNTRACK"
	case PassReasonDefault:
		return "DEFAULT"
	default:
		return "UNKNOWN"
	}
}

// protocolToString maps protocol numbers to human-readable strings
// protocolToString 将协议号映射为可读字符串
func protocolToString(proto uint8) string {
	switch proto {
	case 0:
		return "OTHER"
	case 1:
		return "ICMP"
	case 2:
		return "IGMP"
	case 4:
		return "IP-in-IP"
	case 6:
		return "TCP"
	case 8:
		return "EGP"
	case 17:
		return "UDP"
	case 41:
		return "IPv6"
	case 43:
		return "IPv6-Route"
	case 44:
		return "IPv6-Frag"
	case 47:
		return "GRE"
	case 50:
		return "ESP"
	case 51:
		return "AH"
	case 58:
		return "ICMPv6"
	case 59:
		return "IPv6-NoNxt"
	case 60:
		return "IPv6-Opts"
	case 89:
		return "OSPF"
	case 132:
		return "SCTP"
	case 135:
		return "UDPLite"
	default:
		return fmt.Sprintf("%d", proto)
	}
}

var SystemCmd = &cobra.Command{
	Use:   "system",
	Short: "System management commands",
	Long:  `System management commands for netxfw`,
}

var systemService = services.NewSystemService()
var systemQueryService = services.NewSystemQueryService()

func initCommand(cmd *cobra.Command) {
	configFile, _ := cmd.Flags().GetString("config")
	if configFile != "" {
		commandRuntimeService.SetConfigPath(configFile)
	}
	common.EnsureStandaloneMode()
}

var systemInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize configuration file",
	Long:  `Initialize default configuration file in /root/netxfw/`,
	Run: func(cmd *cobra.Command, args []string) {
		initCommand(cmd)
		systemService.InitConfiguration(cmd.Context())
	},
}

var systemStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show runtime status and statistics",
	Long:  `Show current runtime status and statistics`,
	Run: func(cmd *cobra.Command, args []string) {
		Execute(cmd, args, func(s *sdk.SDK) error {
			return showStatus(cmd.Context(), cmd.OutOrStdout(), s)
		})
	},
}

var systemTestCmd = &cobra.Command{
	Use:   "test",
	Short: "Test configuration validity",
	Long:  `Test configuration validity`,
	Run: func(cmd *cobra.Command, args []string) {
		initCommand(cmd)
		systemService.TestConfiguration(cmd.Context())
	},
}

var systemDaemonCmd = &cobra.Command{
	Use:   "daemon",
	Short: "Start background process",
	Long:  `Start background process`,
	Run: func(cmd *cobra.Command, args []string) {
		initCommand(cmd)
		systemService.RunDaemon(cmd.Context())
	},
}

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

var systemUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Check and install updates",
	Long: `Check for the latest version on GitHub and install it.
This will restart the netxfw service if an update is performed.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("[START] Checking for updates...")
		execCmd := "curl -sSL https://raw.githubusercontent.com/netxfw/netxfw/main/scripts/deploy.sh | bash"
		if err := systemService.RunShellPipeline(execCmd); err != nil {
			reportCommandError(cmd, fmt.Errorf("[ERROR] Update failed: %w", err))
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
	Long:  `Dump runtime BPF maps to configuration files (config.yaml and rules.deny.txt).`,
	Run: func(cmd *cobra.Command, args []string) {
		Execute(cmd, args, func(s *sdk.SDK) error {
			return systemService.SyncRuntimeToConfig(s)
		})
	},
}

var syncToMapCmd = &cobra.Command{
	Use:   "to-map",
	Short: "Apply configuration files to runtime BPF maps",
	Long: `Apply configuration files (config.yaml and rules.deny.txt) to runtime BPF maps.
This will overwrite the runtime state with what is defined in the configuration files.`,
	Run: func(cmd *cobra.Command, args []string) {
		Execute(cmd, args, func(s *sdk.SDK) error {
			return systemService.SyncConfigToRuntimeOverwrite(s)
		})
	},
}

func init() {
	SystemCmd.AddCommand(systemInitCmd)
	SystemCmd.AddCommand(systemStatusCmd)
	SystemCmd.AddCommand(systemTestCmd)
	SystemCmd.AddCommand(systemDaemonCmd)
	SystemCmd.AddCommand(systemUpdateCmd)

	systemLoadCmd.Flags().StringSliceVarP(&interfaces, "interface", "i", nil, "Interfaces to attach XDP to")
	SystemCmd.AddCommand(systemLoadCmd)

	systemAttachCmd.Flags().StringSliceVarP(&interfaces, "interface", "i", nil, "Interfaces to attach XDP to")
	systemAttachCmd.Flags().StringVarP(&xdpMode, "mode", "m", "skb", "XDP attach mode: offload, drv, skb")
	SystemCmd.AddCommand(systemAttachCmd)

	systemUnloadCmd.Flags().StringSliceVarP(&interfaces, "interface", "i", nil, "Interfaces to detach XDP from")
	SystemCmd.AddCommand(systemUnloadCmd)

	systemReloadCmd.Flags().StringSliceVarP(&interfaces, "interface", "i", nil, "Interfaces to attach XDP to")
	SystemCmd.AddCommand(systemReloadCmd)

	SystemCmd.AddCommand(systemOnCmd)
	SystemCmd.AddCommand(systemOffCmd)

	RegisterCommonFlags(systemInitCmd)
	RegisterCommonFlags(systemStatusCmd)
	RegisterCommonFlags(systemTestCmd)
	RegisterCommonFlags(systemDaemonCmd)
	RegisterCommonFlags(systemUpdateCmd)
	RegisterCommonFlags(systemOnCmd)
	RegisterCommonFlags(systemOffCmd)

	SystemCmd.AddCommand(syncCmd)
	syncCmd.AddCommand(syncToConfigCmd)
	syncCmd.AddCommand(syncToMapCmd)
	RegisterCommonFlags(syncToConfigCmd)
	RegisterCommonFlags(syncToMapCmd)
}
