package commands

import (
	"log"
	"os"
	"strconv"

	"github.com/spf13/cobra"
)

var systemCmd = &cobra.Command{
	Use:   "system",
	Short: "System management commands",
	Long:  `System management commands for netxfw`,
}

var systemInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize configuration file",
	Long:  `Initialize default configuration file in /etc/netxfw/`,
	Run: func(cmd *cobra.Command, args []string) {
		if InitConfiguration == nil {
			cmd.PrintErrln("❌ InitConfiguration function not initialized")
			os.Exit(1)
		}
		InitConfiguration()
	},
}

var systemStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show runtime status and statistics",
	Long:  `Show current runtime status and statistics`,
	Run: func(cmd *cobra.Command, args []string) {
		if ShowStatus == nil {
			cmd.PrintErrln("❌ ShowStatus function not initialized")
			os.Exit(1)
		}
		ShowStatus()
	},
}

var systemTestCmd = &cobra.Command{
	Use:   "test",
	Short: "Test configuration validity",
	Long:  `Test configuration validity`,
	Run: func(cmd *cobra.Command, args []string) {
		if TestConfiguration == nil {
			cmd.PrintErrln("❌ TestConfiguration function not initialized")
			os.Exit(1)
		}
		TestConfiguration()
	},
}

var systemDaemonCmd = &cobra.Command{
	Use:   "daemon",
	Short: "Start background process",
	Long:  `Start background process`,
	Run: func(cmd *cobra.Command, args []string) {
		if RunDaemon == nil {
			cmd.PrintErrln("❌ RunDaemon function not initialized")
			os.Exit(1)
		}
		RunDaemon()
	},
}

var systemLoadCmd = &cobra.Command{
	Use:   "load",
	Short: "Load XDP driver",
	Long:  `Load XDP driver`,
	Run: func(cmd *cobra.Command, args []string) {
		if InitConfiguration == nil {
			cmd.PrintErrln("❌ InitConfiguration function not initialized")
			os.Exit(1)
		}
		if InstallXDP == nil {
			cmd.PrintErrln("❌ InstallXDP function not initialized")
			os.Exit(1)
		}
		InitConfiguration()
		InstallXDP()
	},
}

var systemReloadCmd = &cobra.Command{
	Use:   "reload",
	Short: "Smoothly reload XDP (supports capacity adjustment)",
	Long:  `Smoothly reload XDP (supports capacity adjustment)`,
	Run: func(cmd *cobra.Command, args []string) {
		if ReloadXDP == nil {
			cmd.PrintErrln("❌ ReloadXDP function not initialized")
			os.Exit(1)
		}
		ReloadXDP()
	},
}

var systemUnloadCmd = &cobra.Command{
	Use:   "unload",
	Short: "Unload XDP driver",
	Long:  `Unload XDP driver`,
	Run: func(cmd *cobra.Command, args []string) {
		if RemoveXDP == nil {
			cmd.PrintErrln("❌ RemoveXDP function not initialized")
			os.Exit(1)
		}
		RemoveXDP()
	},
}

var systemSetDefaultDenyCmd = &cobra.Command{
	Use:   "set-default-deny [true|false]",
	Short: "Set default deny policy",
	Long:  `Set default deny policy`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if SyncDefaultDeny == nil {
			cmd.PrintErrln("❌ SyncDefaultDeny function not initialized")
			os.Exit(1)
		}
		enable, err := strconv.ParseBool(args[0])
		if err != nil {
			log.Fatalf("❌ Invalid boolean value: %v", err)
		}
		SyncDefaultDeny(enable)
	},
}

var systemRateLimitCmd = &cobra.Command{
	Use:   "ratelimit [true|false]",
	Short: "Enable/disable universal rate limiting",
	Long:  `Enable/disable universal rate limiting`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if SyncEnableRateLimit == nil {
			cmd.PrintErrln("❌ SyncEnableRateLimit function not initialized")
			os.Exit(1)
		}
		enable, err := strconv.ParseBool(args[0])
		if err != nil {
			log.Fatalf("❌ Invalid boolean value: %v", err)
		}
		SyncEnableRateLimit(enable)
	},
}

var systemAFXDPCmd = &cobra.Command{
	Use:   "afxdp [true|false]",
	Short: "Enable/disable AF_XDP redirection",
	Long:  `Enable/disable AF_XDP redirection`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if SyncEnableAFXDP == nil {
			cmd.PrintErrln("❌ SyncEnableAFXDP function not initialized")
			os.Exit(1)
		}
		enable, err := strconv.ParseBool(args[0])
		if err != nil {
			log.Fatalf("❌ Invalid boolean value: %v", err)
		}
		SyncEnableAFXDP(enable)
	},
}

func init() {
	systemCmd.AddCommand(systemInitCmd)
	systemCmd.AddCommand(systemStatusCmd)
	systemCmd.AddCommand(systemTestCmd)
	systemCmd.AddCommand(systemDaemonCmd)
	systemCmd.AddCommand(systemLoadCmd)
	systemCmd.AddCommand(systemReloadCmd)
	systemCmd.AddCommand(systemUnloadCmd)
	systemCmd.AddCommand(systemSetDefaultDenyCmd)
	systemCmd.AddCommand(systemRateLimitCmd)
	systemCmd.AddCommand(systemAFXDPCmd)

	RootCmd.AddCommand(systemCmd)
}
