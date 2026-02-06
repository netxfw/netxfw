package commands

import (
	"log"
	"os"
	"strconv"

	"github.com/spf13/cobra"
)

var portCmd = &cobra.Command{
	Use:   "port",
	Short: "Port management",
	Long:  `Port management commands`,
}

var portAddCmd = &cobra.Command{
	Use:   "add <port>",
	Short: "Add allowed port",
	Long:  `Add port to global allow list`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if EnsureStandaloneMode == nil {
			cmd.PrintErrln("❌ EnsureStandaloneMode function not initialized")
			os.Exit(1)
		}
		if SyncAllowedPort == nil {
			cmd.PrintErrln("❌ SyncAllowedPort function not initialized")
			os.Exit(1)
		}
		EnsureStandaloneMode()
		if len(args) < 1 {
			log.Fatal("❌ Missing port number")
		}
		port, err := strconv.ParseUint(args[0], 10, 16)
		if err != nil {
			log.Fatalf("❌ Invalid port: %v", err)
		}
		SyncAllowedPort(uint16(port), true)
	},
}

var portRemoveCmd = &cobra.Command{
	Use:   "remove <port>",
	Short: "Remove allowed port",
	Long:  `Remove port from global allow list`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if EnsureStandaloneMode == nil {
			cmd.PrintErrln("❌ EnsureStandaloneMode function not initialized")
			os.Exit(1)
		}
		if SyncAllowedPort == nil {
			cmd.PrintErrln("❌ SyncAllowedPort function not initialized")
			os.Exit(1)
		}
		EnsureStandaloneMode()

		port, err := strconv.Atoi(args[0])
		if err != nil {
			log.Fatalf("❌ Invalid port: %v", err)
		}
		SyncAllowedPort(uint16(port), false)
	},
}

func init() {
	portCmd.AddCommand(portAddCmd)
	portCmd.AddCommand(portRemoveCmd)

	RootCmd.AddCommand(portCmd)
}
