package agent

import (
	"log"
	"os"
	"strconv"

	"github.com/livp123/netxfw/cmd/netxfw/commands/common"
	"github.com/spf13/cobra"
)

var PortCmd = &cobra.Command{
	Use:   "port",
	Short: "Allowed ports management",
	Long:  `Allowed ports management commands`,
}

var portAddCmd = &cobra.Command{
	Use:   "add <port>",
	Short: "Add allowed port",
	Long:  `Add port to global allow list`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if common.EnsureStandaloneMode == nil {
			cmd.PrintErrln("❌ common.EnsureStandaloneMode function not initialized")
			os.Exit(1)
		}

		common.EnsureStandaloneMode()

		mgr, err := common.GetManager()
		if err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}
		ctx := cmd.Context()

		if len(args) < 1 {
			log.Fatal("❌ Missing port number")
		}
		port, err := strconv.ParseUint(args[0], 10, 16)
		if err != nil {
			log.Fatalf("❌ Invalid port: %v", err)
		}
		// Add allowed port
		// 添加允许的端口
		if err := common.SyncAllowedPort(ctx, mgr, uint16(port), true); err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}
	},
}

var portRemoveCmd = &cobra.Command{
	Use:   "remove <port>",
	Short: "Remove allowed port",
	Long:  `Remove port from global allow list`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if common.EnsureStandaloneMode == nil {
			cmd.PrintErrln("❌ common.EnsureStandaloneMode function not initialized")
			os.Exit(1)
		}

		common.EnsureStandaloneMode()

		mgr, err := common.GetManager()
		if err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}
		ctx := cmd.Context()

		port, err := strconv.Atoi(args[0])
		if err != nil {
			log.Fatalf("❌ Invalid port: %v", err)
		}
		// Remove allowed port
		// 移除允许的端口
		if err := common.SyncAllowedPort(ctx, mgr, uint16(port), false); err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}
	},
}

func init() {
	PortCmd.AddCommand(portAddCmd)
	PortCmd.AddCommand(portRemoveCmd)
}
