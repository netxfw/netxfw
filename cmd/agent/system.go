package agent

import (
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf/link"
	"github.com/netxfw/netxfw/cmd/common"
	"github.com/netxfw/netxfw/internal/app"
	"github.com/netxfw/netxfw/internal/config"
	"github.com/netxfw/netxfw/internal/core"
	"github.com/netxfw/netxfw/internal/daemon"
	"github.com/netxfw/netxfw/internal/plugins/types"
	"github.com/netxfw/netxfw/internal/runtime"
	"github.com/netxfw/netxfw/internal/utils/fmtutil"
	"github.com/netxfw/netxfw/internal/utils/logger"
	"github.com/netxfw/netxfw/internal/xdp"
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

func initCommand(cmd *cobra.Command) {
	configFile, _ := cmd.Flags().GetString("config")
	if configFile != "" {
		config.SetConfigPath(configFile)
	}
	common.EnsureStandaloneMode()
}

var systemInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize configuration file",
	Long:  `Initialize default configuration file in /root/netxfw/`,
	Run: func(cmd *cobra.Command, args []string) {
		initCommand(cmd)
		core.InitConfiguration(cmd.Context())
	},
}

var systemStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show runtime status and statistics",
	Long:  `Show current runtime status and statistics`,
	Run: func(cmd *cobra.Command, args []string) {
		Execute(cmd, args, func(s *sdk.SDK) error {
			return showStatus(cmd.Context(), s)
		})
	},
}

var systemTestCmd = &cobra.Command{
	Use:   "test",
	Short: "Test configuration validity",
	Long:  `Test configuration validity`,
	Run: func(cmd *cobra.Command, args []string) {
		initCommand(cmd)
		daemon.TestConfiguration(cmd.Context())
	},
}

var systemDaemonCmd = &cobra.Command{
	Use:   "daemon",
	Short: "Start background process",
	Long:  `Start background process`,
	Run: func(cmd *cobra.Command, args []string) {
		initCommand(cmd)
		app.RunDaemon(cmd.Context())
	},
}

var interfaces []string

var xdpMode string

var systemLoadCmd = &cobra.Command{
	Use:   "load",
	Short: "Load XDP driver",
	Long:  `Load XDP driver`,
	Run: func(cmd *cobra.Command, args []string) {
		common.EnsureStandaloneMode()

		if err := app.InstallXDP(cmd.Context(), interfaces); err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
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
		common.EnsureStandaloneMode()

		validModes := map[string]bool{
			"offload": true,
			"drv":     true,
			"skb":     true,
		}
		if !validModes[xdpMode] {
			cmd.PrintErrln("[ERROR] Invalid mode. Must be one of: offload, drv, skb")
			os.Exit(1)
		}

		ifaceList := interfaces
		if len(args) > 0 {
			ifaceList = args
		}

		cfgManager := config.GetConfigManager()
		if err := cfgManager.LoadConfig(); err != nil {
			cmd.PrintErrln("[ERROR] Failed to load config:", err)
			os.Exit(1)
		}
		globalCfg := cfgManager.GetConfig()

		log := logger.Get(cmd.Context())
		manager, err := xdp.NewManager(globalCfg.Capacity, log)
		if err != nil {
			cmd.PrintErrln("[ERROR] Failed to create XDP manager:", err)
			os.Exit(1)
		}

		if pinErr := manager.Pin(config.GetPinPath()); pinErr != nil {
			cmd.PrintErrln("[ERROR] Failed to pin maps:", pinErr)
			os.Exit(1)
		}

		attached, err := attachXDPWithMode(manager, ifaceList, xdpMode)
		if err != nil {
			cmd.PrintErrln("[ERROR] Failed to attach XDP:", err)
			os.Exit(1)
		}

		if len(attached) == 0 {
			cmd.PrintErrln("[ERROR] Failed to attach XDP on any interface")
			os.Exit(1)
		}

		fmt.Printf("[OK] XDP attached successfully on %v with mode: %s\n", attached, xdpMode)
	},
}

var systemUnloadCmd = &cobra.Command{
	Use:   "unload",
	Short: "Unload XDP driver",
	Long:  `Unload XDP driver`,
	Run: func(cmd *cobra.Command, args []string) {
		common.EnsureStandaloneMode()

		if err := app.RemoveXDP(cmd.Context(), interfaces); err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}
	},
}

var systemReloadCmd = &cobra.Command{
	Use:   "reload",
	Short: "Reload configuration and sync to BPF maps",
	Long: `Reload configuration and sync to BPF maps: reads configuration from files and updates BPF maps without reloading XDP program.
This is faster than full reload and maintains existing connections.`,
	Run: func(cmd *cobra.Command, args []string) {
		common.EnsureStandaloneMode()

		configPath := runtime.ConfigPath
		if configPath == "" {
			configPath = config.DefaultConfigPath
		}

		globalCfg, err := types.LoadGlobalConfig(configPath)
		if err != nil {
			cmd.PrintErrln("[ERROR] Failed to load configuration:", err)
			os.Exit(1)
		}

		log := logger.Get(cmd.Context())
		manager, err := xdp.NewManagerFromPins(config.GetPinPath(), log)
		if err != nil {
			cmd.PrintErrln("[ERROR] Failed to load XDP manager:", err)
			os.Exit(1)
		}
		defer manager.Close()

		if err := manager.SyncFromFiles(globalCfg, false); err != nil {
			cmd.PrintErrln("[ERROR] Failed to sync configuration to BPF maps:", err)
			os.Exit(1)
		}

		fmt.Println("[OK] Configuration reloaded and synced to BPF maps successfully")
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
		common.EnsureStandaloneMode()

		ifaceList := interfaces
		if len(args) > 0 {
			ifaceList = args
		}

		if err := app.InstallXDP(cmd.Context(), ifaceList); err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
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
		common.EnsureStandaloneMode()

		ifaceList := interfaces
		if len(args) > 0 {
			ifaceList = args
		}

		if err := app.RemoveXDP(cmd.Context(), ifaceList); err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
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
		if err := fmtutil.RunShellCommand(execCmd); err != nil {
			fmt.Printf("[ERROR] Update failed: %v\n", err)
			os.Exit(1)
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
			cfgPath := config.GetConfigPath()
			cfg, err := types.LoadGlobalConfig(cfgPath)
			if err != nil {
				return fmt.Errorf("failed to load configuration: %w", err)
			}
			return s.Sync.ToConfig(cfg)
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
			cfgPath := config.GetConfigPath()
			cfg, err := types.LoadGlobalConfig(cfgPath)
			if err != nil {
				return fmt.Errorf("failed to load configuration: %w", err)
			}
			return s.Sync.ToMap(cfg, true)
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

func attachXDPWithMode(manager *xdp.Manager, interfaces []string, mode string) ([]string, error) {
	log := logger.Get(nil)
	var attached []string

	var attachMode link.XDPAttachFlags
	var attachModeName string
	switch mode {
	case "offload":
		attachMode = link.XDPOffloadMode
		attachModeName = "Offload"
	case "drv":
		attachMode = link.XDPDriverMode
		attachModeName = "Native"
	case "skb":
		attachMode = link.XDPGenericMode
		attachModeName = "Generic"
	default:
		return nil, fmt.Errorf("invalid mode: %s", mode)
	}

	for _, name := range interfaces {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			log.Warnf("[WARN]  Skip interface %s: %v", name, err)
			continue
		}

		log.Infof("[INFO]  Attempting to attach XDP on %s with mode: %s", name, attachModeName)

		l, err := link.AttachXDP(link.XDPOptions{
			Program:   manager.XdpFirewall(),
			Interface: iface.Index,
			Flags:     attachMode,
		})

		if err == nil {
			linkPath := filepath.Join(config.GetPinPath(), fmt.Sprintf("link_%s", name))
			_ = os.Remove(linkPath)
			if pinErr := l.Pin(linkPath); pinErr != nil {
				log.Warnf("[WARN]  Failed to pin link on %s: %v", name, pinErr)
				l.Close()
				continue
			}
			log.Infof("[OK] Attached XDP on %s (Mode: %s) and pinned link", name, attachModeName)
			attached = append(attached, name)
		} else {
			log.Warnf("[WARN]  Failed to attach XDP on %s using %s mode: %v", name, attachModeName, err)
		}
	}

	return attached, nil
}
