package agent

import (
	"os"
	"strconv"

	"github.com/netxfw/netxfw/cmd/netxfw/commands/common"
	"github.com/netxfw/netxfw/internal/utils/logger"
	"github.com/netxfw/netxfw/pkg/sdk"
	"github.com/spf13/cobra"
)

// getSDKOrExit initializes SDK and exits on error.
// getSDKOrExit 初始化 SDK，出错时退出。
func getSDKOrExit(cmd *cobra.Command) *sdk.SDK {
	common.EnsureStandaloneMode()
	s, err := common.GetSDK()
	if err != nil {
		cmd.PrintErrln(err)
		os.Exit(1)
	}
	return s
}

var QuickBlockCmd = &cobra.Command{
	Use:   "block <ip>",
	Short: "Quickly block an IP",
	Long:  `Quickly block an IP by adding it to the blacklist`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		s := getSDKOrExit(cmd)

		if err := s.Blacklist.Add(args[0]); err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}
		logger.Get(nil).Infof("✅ %s added to blacklist", args[0])
	},
}

var QuickUnlockCmd = &cobra.Command{
	Use:   "unlock <ip>",
	Short: "Quickly unblock IP",
	Long:  `Quickly remove an IP from blacklist`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		s := getSDKOrExit(cmd)

		if err := s.Blacklist.Remove(args[0]); err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}
		logger.Get(nil).Infof("✅ %s removed from blacklist", args[0])
	},
}

var QuickAllowCmd = &cobra.Command{
	Use:   "allow <ip> [port]",
	Short: "Quickly whitelist IP",
	Long:  `Quickly whitelist an IP address`,
	Args:  cobra.RangeArgs(1, 2),
	Run: func(cmd *cobra.Command, args []string) {
		s := getSDKOrExit(cmd)

		var port uint16
		if len(args) > 1 {
			p, err := strconv.ParseUint(args[1], 10, 16)
			if err != nil {
				logger.Get(nil).Fatalf("❌ Invalid port: %v", err)
			}
			port = uint16(p)
		}

		if err := s.Whitelist.Add(args[0], port); err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}
		logger.Get(nil).Infof("✅ %s added to whitelist (port: %d)", args[0], port)
	},
}

var QuickUnallowCmd = &cobra.Command{
	Use:   "unallow <ip> [port]",
	Short: "Quickly remove from whitelist",
	Long:  `Quickly remove an IP from whitelist`,
	Args:  cobra.RangeArgs(1, 2),
	Run: func(cmd *cobra.Command, args []string) {
		s := getSDKOrExit(cmd)

		if err := s.Whitelist.Remove(args[0]); err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}
		logger.Get(nil).Infof("✅ %s removed from whitelist", args[0])
	},
}

var QuickClearCmd = &cobra.Command{
	Use:   "clear",
	Short: "Quickly clear blacklist",
	Long:  `Quickly clear all entries from blacklist`,
	Run: func(cmd *cobra.Command, args []string) {
		s := getSDKOrExit(cmd)

		if common.AskConfirmation("Are you sure you want to clear all entries from the blacklist?") {
			if err := s.Blacklist.Clear(); err != nil {
				cmd.PrintErrln(err)
				os.Exit(1)
			}
			logger.Get(nil).Infof("✅ Blacklist cleared")
		}
	},
}

func init() {
}
