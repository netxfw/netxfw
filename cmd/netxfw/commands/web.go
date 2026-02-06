package commands

import (
	"log"
	"os"
	"strconv"

	"github.com/spf13/cobra"
)

var webCmd = &cobra.Command{
	Use:   "web [port]",
	Short: "Start web management interface",
	Long:  `Start web management interface (default port 11811)`,
	Run: func(cmd *cobra.Command, args []string) {
		if RunWebServer == nil {
			cmd.PrintErrln("❌ RunWebServer function not initialized")
			os.Exit(1)
		}
		port := 11811
		if len(args) > 0 {
			p, err := strconv.Atoi(args[0])
			if err != nil {
				log.Fatalf("❌ Invalid port: %v", err)
			}
			port = p
		}
		RunWebServer(port)
	},
}

func init() {
	RootCmd.AddCommand(webCmd)
}
