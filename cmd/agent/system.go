package agent

import (
	"fmt"

	"github.com/netxfw/netxfw/cmd/common"
	sdk "github.com/netxfw/netxfw/pkg/sdk"
	"github.com/spf13/cobra"
)

var SystemCmd = &cobra.Command{
	Use:   "system",
	Short: "System management commands",
	Long:  `System management commands for netxfw`,
}

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
		if err := systemService.InitConfiguration(cmd.Context()); err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "Error: %v\n", err)
		}
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
		if !systemService.TestConfiguration(cmd.Context()) {
			fmt.Fprintln(cmd.ErrOrStderr(), "Configuration test failed")
		}
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
	SystemCmd.AddCommand(systemCheckCmd)

	SystemCmd.AddCommand(systemOnCmd)
	SystemCmd.AddCommand(systemOffCmd)

	RegisterCommonFlags(systemInitCmd)
	RegisterCommonFlags(systemStatusCmd)
	RegisterCommonFlags(systemTestCmd)
	RegisterCommonFlags(systemDaemonCmd)
	RegisterCommonFlags(systemUpdateCmd)
	RegisterCommonFlags(systemCheckCmd)
	RegisterCommonFlags(systemOnCmd)
	RegisterCommonFlags(systemOffCmd)

	SystemCmd.AddCommand(syncCmd)
	syncCmd.AddCommand(syncToConfigCmd)
	syncCmd.AddCommand(syncToMapCmd)
	RegisterCommonFlags(syncToConfigCmd)
	RegisterCommonFlags(syncToMapCmd)
}
