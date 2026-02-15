package agent

import (
	"os"

	"github.com/livp123/netxfw/cmd/netxfw/commands/common"
	"github.com/spf13/cobra"
)

var syncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Sync configuration between files and runtime BPF maps",
	// Short: 在文件和运行时 BPF Map 之间同步配置
	Long: `Sync configuration between files and runtime BPF maps.`,
	// Long: 在文件和运行时 BPF Map 之间同步配置。
}

var syncToConfigCmd = &cobra.Command{
	Use:   "to-config",
	Short: "Dump runtime BPF maps to configuration files",
	// Short: 将运行时 BPF Map 转储到配置文件
	Long: `Dump runtime BPF maps to configuration files (config.yaml and rules.deny.txt).`,
	// Long: 将运行时 BPF Map 转储到配置文件（config.yaml 和 rules.deny.txt）。
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

		mgr, err := common.GetManager()
		if err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}
		// Dump maps to config files
		// 将 map 转储到配置文件
		if err := common.SyncToConfig(cmd.Context(), mgr); err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}
	},
}

var syncToMapCmd = &cobra.Command{
	Use:   "to-map",
	Short: "Apply configuration files to runtime BPF maps",
	// Short: 将配置文件应用到运行时 BPF Map
	Long: `Apply configuration files (config.yaml and rules.deny.txt) to runtime BPF maps.
This will overwrite the runtime state with what is defined in the configuration files.`,
	// Long: 将配置文件（config.yaml 和 rules.deny.txt）应用到运行时 BPF Map。
	// 这将使用配置文件中定义的内容覆盖运行时状态。
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

		mgr, err := common.GetManager()
		if err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}
		// Load config files to maps
		// 将配置文件加载到 map
		if err := common.SyncToMap(cmd.Context(), mgr); err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}
	},
}

func init() {
	SystemCmd.AddCommand(syncCmd)
	syncCmd.AddCommand(syncToConfigCmd)
	syncCmd.AddCommand(syncToMapCmd)
}
