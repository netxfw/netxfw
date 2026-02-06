package commands

import (
	"os"

	"github.com/spf13/cobra"
)

var conntrackCmd = &cobra.Command{
	Use:   "conntrack",
	Short: "Show active connections",
	Long:  `Show current active connections`,
	Run: func(cmd *cobra.Command, args []string) {
		if EnsureStandaloneMode == nil {
			cmd.PrintErrln("❌ EnsureStandaloneMode function not initialized")
			os.Exit(1)
		}
		if ShowConntrack == nil {
			cmd.PrintErrln("❌ ShowConntrack function not initialized")
			os.Exit(1)
		}
		EnsureStandaloneMode()
		ShowConntrack()
	},
}

func init() {
	RootCmd.AddCommand(conntrackCmd)
}
