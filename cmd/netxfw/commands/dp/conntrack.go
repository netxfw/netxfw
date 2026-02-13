package dp

import (
	"os"

	"github.com/livp123/netxfw/cmd/netxfw/commands/common"
	"github.com/spf13/cobra"
)

var ConntrackCmd = &cobra.Command{
	Use:   "conntrack",
	Short: "Show conntrack table",
	Long:  `Show current connection tracking table`,
	Run: func(cmd *cobra.Command, args []string) {
		if common.EnsureStandaloneMode == nil {
			cmd.PrintErrln("❌ common.EnsureStandaloneMode function not initialized")
			os.Exit(1)
		}
		if common.ShowConntrack == nil {
			cmd.PrintErrln("❌ common.ShowConntrack function not initialized")
			os.Exit(1)
		}
		common.EnsureStandaloneMode()
		// Show conntrack table
		// 显示连接跟踪表
		common.ShowConntrack()
	},
}

func init() {
	// Not adding to RootCmd here
}
