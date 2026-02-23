package agent

import (
	"context"
	"fmt"

	"github.com/netxfw/netxfw/cmd/netxfw/commands/common"
	"github.com/netxfw/netxfw/internal/version"
	"github.com/spf13/cobra"
)

var versionShort bool

var VersionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version information",
	// Short: 显示版本信息
	Long: `Show the current version of netxfw`,
	// Long: 显示 netxfw 的当前版本
	Run: func(cmd *cobra.Command, args []string) {
		if versionShort {
			fmt.Println(version.Version)
			return
		}
		showVersion(cmd.Context())
	},
}

func init() {
	VersionCmd.Flags().BoolVarP(&versionShort, "short", "s", false, "Only print version number")
}

func showVersion(ctx context.Context) {
	fmt.Printf("netxfw %s\n", version.Version)

	s, err := common.GetSDK()
	if err == nil {
		fmt.Println("XDP Status: Running")
		pass, drops, err := s.Stats.GetCounters()
		if err == nil {
			fmt.Printf("Drops: %d, Pass: %d\n", drops, pass)
		}
	} else {
		fmt.Println("XDP Status: Not running or accessible")
	}
}
