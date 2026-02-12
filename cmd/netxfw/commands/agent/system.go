package agent

import (
	"log"
	"os"
	"strconv"

	"github.com/livp123/netxfw/cmd/netxfw/commands/common"
	"github.com/spf13/cobra"
)

var SystemCmd = &cobra.Command{
	Use:   "system",
	Short: "System management commands",
	Long:  `System management commands for netxfw`,
}

var systemInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize configuration file",
	Long:  `Initialize default configuration file in /etc/netxfw/`,
	Run: func(cmd *cobra.Command, args []string) {
		if common.InitConfiguration == nil {
			cmd.PrintErrln("❌ common.InitConfiguration function not initialized")
			os.Exit(1)
		}
		common.InitConfiguration()
	},
}

var systemStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show runtime status and statistics",
	Long:  `Show current runtime status and statistics`,
	Run: func(cmd *cobra.Command, args []string) {
		if common.ShowStatus == nil {
			cmd.PrintErrln("❌ common.ShowStatus function not initialized")
			os.Exit(1)
		}
		common.ShowStatus()
	},
}

var systemTestCmd = &cobra.Command{
	Use:   "test",
	Short: "Test configuration validity",
	Long:  `Test configuration validity`,
	Run: func(cmd *cobra.Command, args []string) {
		if common.TestConfiguration == nil {
			cmd.PrintErrln("❌ common.TestConfiguration function not initialized")
			os.Exit(1)
		}
		common.TestConfiguration()
	},
}

var systemDaemonCmd = &cobra.Command{
	Use:   "daemon",
	Short: "Start background process",
	Long:  `Start background process`,
	Run: func(cmd *cobra.Command, args []string) {
		if common.RunDaemon == nil {
			cmd.PrintErrln("❌ common.RunDaemon function not initialized")
			os.Exit(1)
		}
		common.RunDaemon()
	},
}

var systemLoadCmd = &cobra.Command{
	Use:   "load",
	Short: "Load XDP driver",
	Long:  `Load XDP driver`,
	Run: func(cmd *cobra.Command, args []string) {
		if common.InitConfiguration == nil {
			cmd.PrintErrln("❌ common.InitConfiguration function not initialized")
			os.Exit(1)
		}
		if common.InstallXDP == nil {
			cmd.PrintErrln("❌ common.InstallXDP function not initialized")
			os.Exit(1)
		}
		common.InitConfiguration()
		common.InstallXDP()
	},
}

var systemReloadCmd = &cobra.Command{
	Use:   "reload",
	Short: "Smoothly reload XDP (supports capacity adjustment)",
	Long:  `Smoothly reload XDP (supports capacity adjustment)`,
	Run: func(cmd *cobra.Command, args []string) {
		if common.ReloadXDP == nil {
			cmd.PrintErrln("❌ common.ReloadXDP function not initialized")
			os.Exit(1)
		}
		common.ReloadXDP()
	},
}

var systemUnloadCmd = &cobra.Command{
	Use:   "unload",
	Short: "Unload XDP driver",
	Long:  `Unload XDP driver`,
	Run: func(cmd *cobra.Command, args []string) {
		if common.RemoveXDP == nil {
			cmd.PrintErrln("❌ common.RemoveXDP function not initialized")
			os.Exit(1)
		}
		common.RemoveXDP()
	},
}

var systemSetDefaultDenyCmd = &cobra.Command{
	Use:   "set-default-deny [true|false]",
	Short: "Set default deny policy",
	Long:  `Set default deny policy`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if common.SyncDefaultDeny == nil {
			cmd.PrintErrln("❌ common.SyncDefaultDeny function not initialized")
			os.Exit(1)
		}
		enable, err := strconv.ParseBool(args[0])
		if err != nil {
			log.Fatalf("❌ Invalid boolean value: %v", err)
		}
		common.SyncDefaultDeny(enable)
	},
}

var systemRateLimitCmd = &cobra.Command{
	Use:   "ratelimit [true|false]",
	Short: "Enable/disable universal rate limiting",
	Long:  `Enable/disable universal rate limiting`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if common.SyncEnableRateLimit == nil {
			cmd.PrintErrln("❌ common.SyncEnableRateLimit function not initialized")
			os.Exit(1)
		}
		enable, err := strconv.ParseBool(args[0])
		if err != nil {
			log.Fatalf("❌ Invalid boolean value: %v", err)
		}
		common.SyncEnableRateLimit(enable)
	},
}

var systemAFXDPCmd = &cobra.Command{
	Use:   "afxdp [true|false]",
	Short: "Enable/disable AF_XDP redirection",
	Long:  `Enable/disable AF_XDP redirection`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if common.SyncEnableAFXDP == nil {
			cmd.PrintErrln("❌ common.SyncEnableAFXDP function not initialized")
			os.Exit(1)
		}
		enable, err := strconv.ParseBool(args[0])
		if err != nil {
			log.Fatalf("❌ Invalid boolean value: %v", err)
		}
		common.SyncEnableAFXDP(enable)
	},
}

func init() {
	SystemCmd.AddCommand(systemInitCmd)
	SystemCmd.AddCommand(systemStatusCmd)
	SystemCmd.AddCommand(systemTestCmd)
	SystemCmd.AddCommand(systemDaemonCmd)
	SystemCmd.AddCommand(systemLoadCmd)
	SystemCmd.AddCommand(systemReloadCmd)
	SystemCmd.AddCommand(systemUnloadCmd)
	SystemCmd.AddCommand(systemSetDefaultDenyCmd)
	SystemCmd.AddCommand(systemRateLimitCmd)
	SystemCmd.AddCommand(systemAFXDPCmd)
}
