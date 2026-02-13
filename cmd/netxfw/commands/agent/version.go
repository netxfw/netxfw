package agent

import (
	"fmt"

	"github.com/livp123/netxfw/cmd/netxfw/commands/common"
	"github.com/livp123/netxfw/internal/version"
	"github.com/spf13/cobra"
)

var VersionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version information",
	Long:  `Show the current version of netxfw`,
	Run: func(cmd *cobra.Command, args []string) {
		showVersion()
	},
}

func init() {
	// RootCmd.AddCommand(versionCmd)
}

func showVersion() {
	fmt.Printf("netxfw %s\n", version.Version)
	// Show additional status info if available
	// 如果可用，显示额外的状态信息
	if common.ShowStatus != nil {
		common.ShowStatus()
	}
}
