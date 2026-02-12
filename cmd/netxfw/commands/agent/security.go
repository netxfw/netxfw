package agent

import (
	"log"
	"os"
	"strconv"

	"github.com/livp123/netxfw/cmd/netxfw/commands/common"
	"github.com/spf13/cobra"
)

var SecurityCmd = &cobra.Command{
	Use:   "security",
	Short: "Security management commands",
	Long:  `Security management commands for netxfw`,
}

var securityFragmentsCmd = &cobra.Command{
	Use:   "fragments [true|false]",
	Short: "Drop fragmented packets",
	Long:  `Enable/disable dropping of fragmented packets`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if common.EnsureStandaloneMode == nil {
			cmd.PrintErrln("❌ common.EnsureStandaloneMode function not initialized")
			os.Exit(1)
		}
		if common.SyncDropFragments == nil {
			cmd.PrintErrln("❌ common.SyncDropFragments function not initialized")
			os.Exit(1)
		}
		common.EnsureStandaloneMode()
		enable, err := strconv.ParseBool(args[0])
		if err != nil {
			log.Fatalf("❌ Invalid boolean value: %v", err)
		}
		common.SyncDropFragments(enable)
	},
}

var securityStrictTCPCmd = &cobra.Command{
	Use:   "strict-tcp [true|false]",
	Short: "Strict TCP flag validation",
	Long:  `Enable/disable strict TCP flag validation`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if common.EnsureStandaloneMode == nil {
			cmd.PrintErrln("❌ common.EnsureStandaloneMode function not initialized")
			os.Exit(1)
		}
		if common.SyncStrictTCP == nil {
			cmd.PrintErrln("❌ common.SyncStrictTCP function not initialized")
			os.Exit(1)
		}
		common.EnsureStandaloneMode()
		enable, err := strconv.ParseBool(args[0])
		if err != nil {
			log.Fatalf("❌ Invalid boolean value: %v", err)
		}
		common.SyncStrictTCP(enable)
	},
}

var securitySYNLimitCmd = &cobra.Command{
	Use:   "syn-limit [true|false]",
	Short: "SYN flood protection",
	Long:  `Enable/disable SYN flood protection`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if common.EnsureStandaloneMode == nil {
			cmd.PrintErrln("❌ common.EnsureStandaloneMode function not initialized")
			os.Exit(1)
		}
		if common.SyncSYNLimit == nil {
			cmd.PrintErrln("❌ common.SyncSYNLimit function not initialized")
			os.Exit(1)
		}
		common.EnsureStandaloneMode()
		enable, err := strconv.ParseBool(args[0])
		if err != nil {
			log.Fatalf("❌ Invalid boolean value: %v", err)
		}
		common.SyncSYNLimit(enable)
	},
}

var securityBogonCmd = &cobra.Command{
	Use:   "bogon [true|false]",
	Short: "Bogon filtering",
	Long:  `Enable/disable Bogon filtering`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if common.EnsureStandaloneMode == nil {
			cmd.PrintErrln("❌ common.EnsureStandaloneMode function not initialized")
			os.Exit(1)
		}
		if common.SyncBogonFilter == nil {
			cmd.PrintErrln("❌ common.SyncBogonFilter function not initialized")
			os.Exit(1)
		}
		common.EnsureStandaloneMode()
		enable, err := strconv.ParseBool(args[0])
		if err != nil {
			log.Fatalf("❌ Invalid boolean value: %v", err)
		}
		common.SyncBogonFilter(enable)
	},
}

var securityAutoBlockCmd = &cobra.Command{
	Use:   "auto-block [true|false]",
	Short: "Auto-blocking",
	Long:  `Enable/disable auto-blocking`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if common.EnsureStandaloneMode == nil {
			cmd.PrintErrln("❌ common.EnsureStandaloneMode function not initialized")
			os.Exit(1)
		}
		if common.SyncAutoBlock == nil {
			cmd.PrintErrln("❌ common.SyncAutoBlock function not initialized")
			os.Exit(1)
		}
		common.EnsureStandaloneMode()
		enable, err := strconv.ParseBool(args[0])
		if err != nil {
			log.Fatalf("❌ Invalid boolean value: %v", err)
		}
		common.SyncAutoBlock(enable)
	},
}

var securityAutoBlockExpiryCmd = &cobra.Command{
	Use:   "auto-block-expiry <seconds>",
	Short: "Auto-block expiry time",
	Long:  `Set auto-block expiry time in seconds`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if common.EnsureStandaloneMode == nil {
			cmd.PrintErrln("❌ common.EnsureStandaloneMode function not initialized")
			os.Exit(1)
		}
		if common.SyncAutoBlockExpiry == nil {
			cmd.PrintErrln("❌ common.SyncAutoBlockExpiry function not initialized")
			os.Exit(1)
		}
		common.EnsureStandaloneMode()
		expiry, err := strconv.Atoi(args[0])
		if err != nil {
			log.Fatalf("❌ Invalid expiry value: %v", err)
		}
		common.SyncAutoBlockExpiry(uint32(expiry))
	},
}

func init() {
	SecurityCmd.AddCommand(securityFragmentsCmd)
	SecurityCmd.AddCommand(securityStrictTCPCmd)
	SecurityCmd.AddCommand(securitySYNLimitCmd)
	SecurityCmd.AddCommand(securityBogonCmd)
	SecurityCmd.AddCommand(securityAutoBlockCmd)
	SecurityCmd.AddCommand(securityAutoBlockExpiryCmd)
}
