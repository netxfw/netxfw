package agent

import (
	"log"
	"os"
	"strconv"

	"github.com/livp123/netxfw/cmd/netxfw/commands/common"
	"github.com/spf13/cobra"
)

var QuickBlockCmd = &cobra.Command{
	Use:   "block <ip>",
	Short: "Quickly block an IP",
	Long:  `Quickly block an IP by adding it to the blacklist`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if common.EnsureStandaloneMode == nil {
			cmd.PrintErrln("❌ common.EnsureStandaloneMode function not initialized")
			os.Exit(1)
		}
		if common.SyncLockMap == nil {
			cmd.PrintErrln("❌ common.SyncLockMap function not initialized")
			os.Exit(1)
		}
		common.EnsureStandaloneMode()
		common.SyncLockMap(args[0], true)
	},
}

var QuickUnlockCmd = &cobra.Command{
	Use:   "unlock <ip>",
	Short: "Quickly unblock IP",
	Long:  `Quickly remove an IP from blacklist`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if common.EnsureStandaloneMode == nil {
			cmd.PrintErrln("❌ common.EnsureStandaloneMode function not initialized")
			os.Exit(1)
		}
		if common.SyncLockMap == nil {
			cmd.PrintErrln("❌ common.SyncLockMap function not initialized")
			os.Exit(1)
		}
		common.EnsureStandaloneMode()
		common.SyncLockMap(args[0], false)
	},
}

var QuickAllowCmd = &cobra.Command{
	Use:   "allow <ip> [port]",
	Short: "Quickly whitelist IP",
	Long:  `Quickly whitelist an IP address`,
	Args:  cobra.RangeArgs(1, 2),
	Run: func(cmd *cobra.Command, args []string) {
		if common.EnsureStandaloneMode == nil {
			cmd.PrintErrln("❌ common.EnsureStandaloneMode function not initialized")
			os.Exit(1)
		}
		if common.SyncWhitelistMap == nil {
			cmd.PrintErrln("❌ common.SyncWhitelistMap function not initialized")
			os.Exit(1)
		}
		common.EnsureStandaloneMode()
		var port uint16
		if len(args) > 1 {
			p, err := strconv.ParseUint(args[1], 10, 16)
			if err != nil {
				log.Fatalf("❌ Invalid port: %v", err)
			}
			port = uint16(p)
		}
		common.SyncWhitelistMap(args[0], port, true)
	},
}

var QuickUnallowCmd = &cobra.Command{
	Use:   "unallow <ip> [port]",
	Short: "Quickly remove from whitelist",
	Long:  `Quickly remove an IP from whitelist`,
	Args:  cobra.RangeArgs(1, 2),
	Run: func(cmd *cobra.Command, args []string) {
		if common.EnsureStandaloneMode == nil {
			cmd.PrintErrln("❌ common.EnsureStandaloneMode function not initialized")
			os.Exit(1)
		}
		if common.SyncWhitelistMap == nil {
			cmd.PrintErrln("❌ common.SyncWhitelistMap function not initialized")
			os.Exit(1)
		}
		common.EnsureStandaloneMode()
		var port uint16
		if len(args) > 1 {
			p, err := strconv.ParseUint(args[1], 10, 16)
			if err != nil {
				log.Fatalf("❌ Invalid port: %v", err)
			}
			port = uint16(p)
		}
		common.SyncWhitelistMap(args[0], port, false)
	},
}

var QuickClearCmd = &cobra.Command{
	Use:   "clear",
	Short: "Quickly clear blacklist",
	Long:  `Quickly clear all entries from blacklist`,
	Run: func(cmd *cobra.Command, args []string) {
		if common.EnsureStandaloneMode == nil {
			cmd.PrintErrln("❌ common.EnsureStandaloneMode function not initialized")
			os.Exit(1)
		}
		if common.ClearBlacklist == nil {
			cmd.PrintErrln("❌ common.ClearBlacklist function not initialized")
			os.Exit(1)
		}
		if common.AskConfirmation == nil {
			cmd.PrintErrln("❌ common.AskConfirmation function not initialized")
			os.Exit(1)
		}
		common.EnsureStandaloneMode()
		if common.AskConfirmation("Are you sure you want to clear all entries from the blacklist?") {
			common.ClearBlacklist()
		}
	},
}

func init() {
	// Not adding to RootCmd here, will be added in root.go
}
