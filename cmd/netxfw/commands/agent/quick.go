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

		common.EnsureStandaloneMode()

		mgr, err := common.GetManager()
		if err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}
		ctx := cmd.Context()

		// Block IP
		// 封锁 IP
		if err := common.SyncLockMap(ctx, mgr, args[0], true); err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}
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

		common.EnsureStandaloneMode()

		mgr, err := common.GetManager()
		if err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}
		ctx := cmd.Context()

		// Unblock IP
		// 解封 IP
		if err := common.SyncLockMap(ctx, mgr, args[0], false); err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}
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

		common.EnsureStandaloneMode()

		mgr, err := common.GetManager()
		if err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}
		ctx := cmd.Context()

		var port uint16
		if len(args) > 1 {
			p, err := strconv.ParseUint(args[1], 10, 16)
			if err != nil {
				log.Fatalf("❌ Invalid port: %v", err)
			}
			port = uint16(p)
		}
		// Allow IP
		// 允许 IP
		if err := common.SyncWhitelistMap(ctx, mgr, args[0], port, true); err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}
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

		common.EnsureStandaloneMode()

		mgr, err := common.GetManager()
		if err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}
		ctx := cmd.Context()

		var port uint16
		if len(args) > 1 {
			p, err := strconv.ParseUint(args[1], 10, 16)
			if err != nil {
				log.Fatalf("❌ Invalid port: %v", err)
			}
			port = uint16(p)
		}
		// Unallow IP
		// 取消允许 IP
		if err := common.SyncWhitelistMap(ctx, mgr, args[0], port, false); err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}
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
		if common.AskConfirmation == nil {
			cmd.PrintErrln("❌ common.AskConfirmation function not initialized")
			os.Exit(1)
		}

		common.EnsureStandaloneMode()

		mgr, err := common.GetManager()
		if err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}
		ctx := cmd.Context()

		// Confirm and clear blacklist
		// 确认并清空黑名单
		if common.AskConfirmation("Are you sure you want to clear all entries from the blacklist?") {
			if err := common.ClearBlacklist(ctx, mgr); err != nil {
				cmd.PrintErrln(err)
				os.Exit(1)
			}
		}
	},
}

func init() {
	// Not adding to RootCmd here, will be added in root.go
}
