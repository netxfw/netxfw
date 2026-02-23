package agent

import (
	"fmt"
	"strconv"

	"github.com/netxfw/netxfw/internal/utils/logger"
	"github.com/netxfw/netxfw/pkg/sdk"
	"github.com/spf13/cobra"
)

var PortCmd = &cobra.Command{
	Use:   "port",
	Short: "Allowed ports management",
	// Short: 允许端口管理
	Long: `Allowed ports management commands`,
	// Long: 允许端口管理命令
}

var portAddCmd = &cobra.Command{
	Use:   "add <port>",
	Short: "Add allowed port",
	Long:  `Add port to global allow list`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		Execute(cmd, args, func(s *sdk.SDK) error {
			port, err := strconv.ParseUint(args[0], 10, 16)
			if err != nil {
				return fmt.Errorf("❌ Invalid port: %v", err)
			}
			if err := s.Rule.AllowPort(uint16(port)); err != nil {
				return err
			}
			logger.Get(cmd.Context()).Infof("✅ Port %d added to allowed list", port)
			return nil
		})
	},
}

var portRemoveCmd = &cobra.Command{
	Use:   "remove <port>",
	Short: "Remove allowed port",
	Long:  `Remove port from global allow list`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		Execute(cmd, args, func(s *sdk.SDK) error {
			port, err := strconv.Atoi(args[0])
			if err != nil {
				return fmt.Errorf("❌ Invalid port: %v", err)
			}
			if err := s.Rule.RemoveAllowedPort(uint16(port)); err != nil {
				return err
			}
			logger.Get(cmd.Context()).Infof("✅ Port %d removed from allowed list", port)
			return nil
		})
	},
}

func init() {
	PortCmd.AddCommand(portAddCmd)
	PortCmd.AddCommand(portRemoveCmd)

	RegisterCommonFlags(portAddCmd)
	RegisterCommonFlags(portRemoveCmd)
}
