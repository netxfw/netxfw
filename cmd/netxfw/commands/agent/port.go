package agent

import (
	"os"
	"strconv"

	"github.com/netxfw/netxfw/cmd/netxfw/commands/common"
	"github.com/netxfw/netxfw/internal/utils/logger"
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
	// Short: 添加允许端口
	Long: `Add port to global allow list`,
	// Long: 将端口添加到全局允许列表
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		common.EnsureStandaloneMode()

		s, err := common.GetSDK()
		if err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}

		if len(args) < 1 {
			logger.Get(cmd.Context()).Fatalf("❌ Missing port number")
		}
		port, err := strconv.ParseUint(args[0], 10, 16)
		if err != nil {
			logger.Get(cmd.Context()).Fatalf("❌ Invalid port: %v", err)
		}
		// Add allowed port
		// 添加允许的端口
		if err := s.Rule.AllowPort(uint16(port)); err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}
		logger.Get(cmd.Context()).Infof("✅ Port %d added to allowed list", port)
	},
}

var portRemoveCmd = &cobra.Command{
	Use:   "remove <port>",
	Short: "Remove allowed port",
	// Short: 移除允许端口
	Long: `Remove port from global allow list`,
	// Long: 从全局允许列表移除端口
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		common.EnsureStandaloneMode()

		s, err := common.GetSDK()
		if err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}

		port, err := strconv.Atoi(args[0])
		if err != nil {
			logger.Get(cmd.Context()).Fatalf("❌ Invalid port: %v", err)
		}
		// Remove allowed port
		// 移除允许的端口
		if err := s.Rule.RemoveAllowedPort(uint16(port)); err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}
		logger.Get(cmd.Context()).Infof("✅ Port %d removed from allowed list", port)
	},
}

func init() {
	PortCmd.AddCommand(portAddCmd)
	PortCmd.AddCommand(portRemoveCmd)
}
