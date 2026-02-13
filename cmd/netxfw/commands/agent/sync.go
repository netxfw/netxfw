package agent

import (
	"os"

	"github.com/livp123/netxfw/cmd/netxfw/commands/common"
	"github.com/spf13/cobra"
)

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
		if common.EnsureStandaloneMode == nil {
			cmd.PrintErrln("❌ common.EnsureStandaloneMode function not initialized")
			os.Exit(1)
		}
		common.EnsureStandaloneMode()

		if common.SyncToConfig == nil {
			cmd.PrintErrln("❌ common.SyncToConfig function not initialized")
			os.Exit(1)
		}
		// Dump maps to config files
		// 将 map 转储到配置文件
		common.SyncToConfig()
	},
}

var syncToMapCmd = &cobra.Command{
	Use:   "to-map",
	Short: "Apply configuration files to runtime BPF maps",
	Long: `Apply configuration files (config.yaml and rules.deny.txt) to runtime BPF maps.
This will overwrite the runtime state with what is defined in the configuration files.`,
	Run: func(cmd *cobra.Command, args []string) {
		if common.EnsureStandaloneMode == nil {
			cmd.PrintErrln("❌ common.EnsureStandaloneMode function not initialized")
			os.Exit(1)
		}
		common.EnsureStandaloneMode()

		if common.SyncToMap == nil {
			cmd.PrintErrln("❌ common.SyncToMap function not initialized")
			os.Exit(1)
		}
		// Load config files to maps
		// 将配置文件加载到 map
		common.SyncToMap()
	},
}

func init() {
	SystemCmd.AddCommand(syncCmd)
	syncCmd.AddCommand(syncToConfigCmd)
	syncCmd.AddCommand(syncToMapCmd)
}
