package agent

import (
	"fmt"
	"strconv"

	"github.com/netxfw/netxfw/cmd/netxfw/commands/common"
	"github.com/netxfw/netxfw/internal/utils/logger"
	"github.com/netxfw/netxfw/pkg/sdk"
	"github.com/spf13/cobra"
)

var QuickBlockCmd = &cobra.Command{
	Use:   "block <ip>",
	Short: "Quickly block an IP",
	Long:  `Quickly block an IP by adding it to the blacklist`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		Execute(cmd, args, func(s *sdk.SDK) error {
			if err := s.Blacklist.Add(args[0]); err != nil {
				return err
			}
			logger.Get(cmd.Context()).Infof("✅ %s added to blacklist", args[0])
			return nil
		})
	},
}

var QuickUnlockCmd = &cobra.Command{
	Use:   "unlock <ip>",
	Short: "Quickly unblock IP",
	Long:  `Quickly remove an IP from blacklist`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		Execute(cmd, args, func(s *sdk.SDK) error {
			if err := s.Blacklist.Remove(args[0]); err != nil {
				return err
			}
			logger.Get(cmd.Context()).Infof("✅ %s removed from blacklist", args[0])
			return nil
		})
	},
}

var QuickAllowCmd = &cobra.Command{
	Use:   "allow <ip> [port]",
	Short: "Quickly whitelist IP",
	Long:  `Quickly whitelist an IP address`,
	Args:  cobra.RangeArgs(1, 2),
	Run: func(cmd *cobra.Command, args []string) {
		Execute(cmd, args, func(s *sdk.SDK) error {
			var port uint16
			if len(args) > 1 {
				p, err := strconv.ParseUint(args[1], 10, 16)
				if err != nil {
					return fmt.Errorf("❌ Invalid port: %v", err)
				}
				port = uint16(p)
			}

			if err := s.Whitelist.Add(args[0], port); err != nil {
				return err
			}
			logger.Get(cmd.Context()).Infof("✅ %s added to whitelist (port: %d)", args[0], port)
			return nil
		})
	},
}

var QuickUnallowCmd = &cobra.Command{
	Use:   "unallow <ip> [port]",
	Short: "Quickly remove from whitelist",
	Long:  `Quickly remove an IP from whitelist`,
	Args:  cobra.RangeArgs(1, 2),
	Run: func(cmd *cobra.Command, args []string) {
		Execute(cmd, args, func(s *sdk.SDK) error {
			if err := s.Whitelist.Remove(args[0]); err != nil {
				return err
			}
			logger.Get(cmd.Context()).Infof("✅ %s removed from whitelist", args[0])
			return nil
		})
	},
}

var QuickClearCmd = &cobra.Command{
	Use:   "clear",
	Short: "Quickly clear blacklist",
	Long:  `Quickly clear all entries from blacklist`,
	Run: func(cmd *cobra.Command, args []string) {
		Execute(cmd, args, func(s *sdk.SDK) error {
			if common.AskConfirmation("Are you sure you want to clear all entries from the blacklist?") {
				if err := s.Blacklist.Clear(); err != nil {
					return err
				}
				logger.Get(cmd.Context()).Infof("✅ Blacklist cleared")
			}
			return nil
		})
	},
}

// QuickLockCmd is an alias for QuickBlockCmd (backward-compatible)
// QuickLockCmd 是 QuickBlockCmd 的别名（向后兼容）
var QuickLockCmd = &cobra.Command{
	Use:        "lock <ip>",
	Short:      "Block an IP (alias for 'block')",
	Long:       `Block an IP by adding it to the blacklist. This is an alias for 'block'.`,
	Args:       cobra.ExactArgs(1),
	Deprecated: "use 'block' instead",
	Run:        QuickBlockCmd.Run,
}

func init() {
	RegisterCommonFlags(QuickBlockCmd)
	RegisterCommonFlags(QuickUnlockCmd)
	RegisterCommonFlags(QuickAllowCmd)
	RegisterCommonFlags(QuickUnallowCmd)
	RegisterCommonFlags(QuickClearCmd)
	RegisterCommonFlags(QuickLockCmd)
}
