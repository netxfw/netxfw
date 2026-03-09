package agent

import (
	"fmt"

	"github.com/netxfw/netxfw/internal/config"
	"github.com/netxfw/netxfw/internal/plugins/types"
	"github.com/netxfw/netxfw/pkg/sdk"
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
		Execute(cmd, args, func(s *sdk.SDK) error {
			// Load global config to pass to Sync
			cfgPath := config.GetConfigPath()
			cfg, err := types.LoadGlobalConfig(cfgPath)
			if err != nil {
				return fmt.Errorf("failed to load configuration: %w", err)
			}

			// Dump maps to config files
			// 将 map 转储到配置文件
			return s.Sync.ToConfig(cfg)
		})
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
		Execute(cmd, args, func(s *sdk.SDK) error {
			// Load global config
			cfgPath := config.GetConfigPath()
			cfg, err := types.LoadGlobalConfig(cfgPath)
			if err != nil {
				return fmt.Errorf("failed to load configuration: %w", err)
			}

			// Load config files to maps
			// 将配置文件加载到 map
			return s.Sync.ToMap(cfg, true)
		})
	},
}

func init() {
	SystemCmd.AddCommand(syncCmd)
	syncCmd.AddCommand(syncToConfigCmd)
	syncCmd.AddCommand(syncToMapCmd)

	RegisterCommonFlags(syncToConfigCmd)
	RegisterCommonFlags(syncToMapCmd)
}
