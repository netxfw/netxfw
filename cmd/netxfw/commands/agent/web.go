package agent

import (
	"log"
	"os"
	"strconv"

	"github.com/livp123/netxfw/cmd/netxfw/commands/common"
	"github.com/spf13/cobra"
)

var WebCmd = &cobra.Command{
	Use:   "web [port]",
	Short: "Start web interface",
	Long:  `Start the web management interface (default port 11811)`,
	Run: func(cmd *cobra.Command, args []string) {
		if common.RunWebServer == nil {
			cmd.PrintErrln("❌ common.RunWebServer function not initialized")
			os.Exit(1)
		}
		
		ctx := cmd.Context()
		
		port := 11811
		if len(args) > 0 {
			p, err := strconv.Atoi(args[0])
			if err != nil {
				log.Fatalf("❌ Invalid port: %v", err)
			}
			port = p
		}
		// Start web server
		// 启动 Web 服务器
		common.RunWebServer(ctx, port)
	},
}

func init() {
	// Not adding to RootCmd here
}
