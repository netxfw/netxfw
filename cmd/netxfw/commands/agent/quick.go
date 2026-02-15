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
	// Short: 快速封锁 IP
	Long: `Quickly block an IP by adding it to the blacklist`,
	// Long: 通过将其添加到黑名单来快速封锁 IP
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		common.EnsureStandaloneMode()

		s, err := common.GetSDK()
		if err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}

		// Block IP
		// 封锁 IP
		if err := s.Blacklist.Add(args[0]); err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}
		log.Printf("✅ %s added to blacklist", args[0])
	},
}

var QuickUnlockCmd = &cobra.Command{
	Use:   "unlock <ip>",
	Short: "Quickly unblock IP",
	// Short: 快速解封 IP
	Long: `Quickly remove an IP from blacklist`,
	// Long: 快速从黑名单中移除 IP
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		common.EnsureStandaloneMode()

		s, err := common.GetSDK()
		if err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}

		// Unblock IP
		// 解封 IP
		if err := s.Blacklist.Remove(args[0]); err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}
		log.Printf("✅ %s removed from blacklist", args[0])
	},
}

var QuickAllowCmd = &cobra.Command{
	Use:   "allow <ip> [port]",
	Short: "Quickly whitelist IP",
	// Short: 快速将 IP 加入白名单
	Long: `Quickly whitelist an IP address`,
	// Long: 快速将一个 IP 地址加入白名单
	Args: cobra.RangeArgs(1, 2),
	Run: func(cmd *cobra.Command, args []string) {
		common.EnsureStandaloneMode()

		s, err := common.GetSDK()
		if err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}

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
		if err := s.Whitelist.Add(args[0], port); err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}
		log.Printf("✅ %s added to whitelist (port: %d)", args[0], port)
	},
}

var QuickUnallowCmd = &cobra.Command{
	Use:   "unallow <ip> [port]",
	Short: "Quickly remove from whitelist",
	// Short: 快速从白名单中移除
	Long: `Quickly remove an IP from whitelist`,
	// Long: 快速从白名单中移除一个 IP
	Args: cobra.RangeArgs(1, 2),
	Run: func(cmd *cobra.Command, args []string) {
		common.EnsureStandaloneMode()

		s, err := common.GetSDK()
		if err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}

		// Unallow IP
		// 取消允许 IP
		if err := s.Whitelist.Remove(args[0]); err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}
		log.Printf("✅ %s removed from whitelist", args[0])
	},
}

var QuickClearCmd = &cobra.Command{
	Use:   "clear",
	Short: "Quickly clear blacklist",
	// Short: 快速清空黑名单
	Long: `Quickly clear all entries from blacklist`,
	// Long: 快速清空黑名单中的所有条目
	Run: func(cmd *cobra.Command, args []string) {
		common.EnsureStandaloneMode()

		s, err := common.GetSDK()
		if err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}

		// Confirm and clear blacklist
		// 确认并清空黑名单
		if common.AskConfirmation("Are you sure you want to clear all entries from the blacklist?") {
			if err := s.Blacklist.Clear(); err != nil {
				cmd.PrintErrln(err)
				os.Exit(1)
			}
			log.Println("✅ Blacklist cleared")
		}
	},
}

func init() {
	// Not adding to RootCmd here, will be added in root.go
}
