package commands

import (
	"log"
	"os"
	"strconv"

	"github.com/spf13/cobra"
)

var lockCmd = &cobra.Command{
	Use:   "lock <ip>",
	Short: "Quickly block IP",
	Long:  `Quickly block an IP address`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if EnsureStandaloneMode == nil {
			cmd.PrintErrln("❌ EnsureStandaloneMode function not initialized")
			os.Exit(1)
		}
		if SyncLockMap == nil {
			cmd.PrintErrln("❌ SyncLockMap function not initialized")
			os.Exit(1)
		}
		EnsureStandaloneMode()
		SyncLockMap(args[0], true)
	},
}

var unlockCmd = &cobra.Command{
	Use:   "unlock <ip>",
	Short: "Quickly unblock IP",
	Long:  `Quickly unblock an IP address`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if EnsureStandaloneMode == nil {
			cmd.PrintErrln("❌ EnsureStandaloneMode function not initialized")
			os.Exit(1)
		}
		if SyncLockMap == nil {
			cmd.PrintErrln("❌ SyncLockMap function not initialized")
			os.Exit(1)
		}
		EnsureStandaloneMode()
		SyncLockMap(args[0], false)
	},
}

var allowCmd = &cobra.Command{
	Use:   "allow <ip> [port]",
	Short: "Quickly whitelist IP",
	Long:  `Quickly whitelist an IP address`,
	Args:  cobra.RangeArgs(1, 2),
	Run: func(cmd *cobra.Command, args []string) {
		if EnsureStandaloneMode == nil {
			cmd.PrintErrln("❌ EnsureStandaloneMode function not initialized")
			os.Exit(1)
		}
		if SyncWhitelistMap == nil {
			cmd.PrintErrln("❌ SyncWhitelistMap function not initialized")
			os.Exit(1)
		}
		EnsureStandaloneMode()
		var port uint16
		if len(args) > 1 {
			p, err := strconv.ParseUint(args[1], 10, 16)
			if err != nil {
				log.Fatalf("❌ Invalid port: %v", err)
			}
			port = uint16(p)
		}
		SyncWhitelistMap(args[0], port, true)
	},
}

var unallowCmd = &cobra.Command{
	Use:   "unallow <ip> [port]",
	Short: "Quickly remove from whitelist",
	Long:  `Quickly remove an IP from whitelist`,
	Args:  cobra.RangeArgs(1, 2),
	Run: func(cmd *cobra.Command, args []string) {
		if EnsureStandaloneMode == nil {
			cmd.PrintErrln("❌ EnsureStandaloneMode function not initialized")
			os.Exit(1)
		}
		if SyncWhitelistMap == nil {
			cmd.PrintErrln("❌ SyncWhitelistMap function not initialized")
			os.Exit(1)
		}
		EnsureStandaloneMode()
		var port uint16
		if len(args) > 1 {
			p, err := strconv.ParseUint(args[1], 10, 16)
			if err != nil {
				log.Fatalf("❌ Invalid port: %v", err)
			}
			port = uint16(p)
		}
		SyncWhitelistMap(args[0], port, false)
	},
}

var clearCmd = &cobra.Command{
	Use:   "clear",
	Short: "Quickly clear blacklist",
	Long:  `Quickly clear all entries from blacklist`,
	Run: func(cmd *cobra.Command, args []string) {
		if EnsureStandaloneMode == nil {
			cmd.PrintErrln("❌ EnsureStandaloneMode function not initialized")
			os.Exit(1)
		}
		if ClearBlacklist == nil {
			cmd.PrintErrln("❌ ClearBlacklist function not initialized")
			os.Exit(1)
		}
		if AskConfirmation == nil {
			cmd.PrintErrln("❌ AskConfirmation function not initialized")
			os.Exit(1)
		}
		EnsureStandaloneMode()
		if AskConfirmation("Are you sure you want to clear all entries from the blacklist?") {
			ClearBlacklist()
		}
	},
}

func init() {
	RootCmd.AddCommand(lockCmd)
	RootCmd.AddCommand(unlockCmd)
	RootCmd.AddCommand(allowCmd)
	RootCmd.AddCommand(unallowCmd)
	RootCmd.AddCommand(clearCmd)
}
