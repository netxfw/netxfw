package agent

import (
	"fmt"
	"os"

	"github.com/livp123/netxfw/internal/config"
	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/spf13/cobra"
)

var WebCmd = &cobra.Command{
	Use:   "web",
	Short: "Show web interface information",
	// Short: 显示 Web 界面信息
	Long: `Show the URL and status of the web management interface.
To enable or disable the web interface, edit the configuration file.`,
	// Long: 显示 Web 管理界面的 URL 和状态。
	// 若要启用或禁用 Web 界面，请编辑配置文件。
	Run: func(cmd *cobra.Command, args []string) {
		cfgPath := config.GetConfigPath()
		cfg, err := types.LoadGlobalConfig(cfgPath)
		if err != nil {
			cmd.PrintErrln("❌ Failed to load configuration:", err)
			os.Exit(1)
		}

		if !cfg.Web.Enabled {
			fmt.Println("⚪ Web interface is DISABLED in configuration.")
			fmt.Printf("To enable it, set 'web.enabled: true' in %s and restart the agent.\n", cfgPath)
			return
		}

		port := cfg.Web.Port
		if port == 0 {
			port = 11811 // Default port
		}

		fmt.Printf("🟢 Web interface is ENABLED.\n")
		fmt.Printf("📂 Configuration: %s\n", cfgPath)
		fmt.Printf("🔗 URL: http://localhost:%d\n", port)
		if cfg.Web.Token != "" {
			fmt.Printf("🔑 Token: %s\n", cfg.Web.Token)
		} else {
			fmt.Println("🔑 Token: (will be auto-generated on first start)")
		}

		// Check if agent is running
		pidBytes, err := os.ReadFile(config.DefaultPidPath)
		if err == nil {
			fmt.Printf("🏃 Agent Status: Running (PID: %s)\n", string(pidBytes))
		} else {
			fmt.Printf("🛑 Agent Status: Not Running (or PID file not found at %s)\n", config.DefaultPidPath)
		}
	},
}

func init() {
	// Not adding to RootCmd here
}
