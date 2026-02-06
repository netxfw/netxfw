package commands

import (
	"log"
	"os"
	"strconv"

	"github.com/spf13/cobra"
)

var securityCmd = &cobra.Command{
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
		if EnsureStandaloneMode == nil {
			cmd.PrintErrln("❌ EnsureStandaloneMode function not initialized")
			os.Exit(1)
		}
		if SyncDropFragments == nil {
			cmd.PrintErrln("❌ SyncDropFragments function not initialized")
			os.Exit(1)
		}
		EnsureStandaloneMode()
		enable, err := strconv.ParseBool(args[0])
		if err != nil {
			log.Fatalf("❌ Invalid boolean value: %v", err)
		}
		SyncDropFragments(enable)
	},
}

var securityStrictTCPCmd = &cobra.Command{
	Use:   "strict-tcp [true|false]",
	Short: "Strict TCP flag validation",
	Long:  `Enable/disable strict TCP flag validation`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if EnsureStandaloneMode == nil {
			cmd.PrintErrln("❌ EnsureStandaloneMode function not initialized")
			os.Exit(1)
		}
		if SyncStrictTCP == nil {
			cmd.PrintErrln("❌ SyncStrictTCP function not initialized")
			os.Exit(1)
		}
		EnsureStandaloneMode()
		enable, err := strconv.ParseBool(args[0])
		if err != nil {
			log.Fatalf("❌ Invalid boolean value: %v", err)
		}
		SyncStrictTCP(enable)
	},
}

var securitySYNLimitCmd = &cobra.Command{
	Use:   "syn-limit [true|false]",
	Short: "SYN flood protection",
	Long:  `Enable/disable SYN flood protection`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if EnsureStandaloneMode == nil {
			cmd.PrintErrln("❌ EnsureStandaloneMode function not initialized")
			os.Exit(1)
		}
		if SyncSYNLimit == nil {
			cmd.PrintErrln("❌ SyncSYNLimit function not initialized")
			os.Exit(1)
		}
		EnsureStandaloneMode()
		enable, err := strconv.ParseBool(args[0])
		if err != nil {
			log.Fatalf("❌ Invalid boolean value: %v", err)
		}
		SyncSYNLimit(enable)
	},
}

var securityBogonCmd = &cobra.Command{
	Use:   "bogon [true|false]",
	Short: "Bogon filtering",
	Long:  `Enable/disable Bogon filtering`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if EnsureStandaloneMode == nil {
			cmd.PrintErrln("❌ EnsureStandaloneMode function not initialized")
			os.Exit(1)
		}
		if SyncBogonFilter == nil {
			cmd.PrintErrln("❌ SyncBogonFilter function not initialized")
			os.Exit(1)
		}
		EnsureStandaloneMode()
		enable, err := strconv.ParseBool(args[0])
		if err != nil {
			log.Fatalf("❌ Invalid boolean value: %v", err)
		}
		SyncBogonFilter(enable)
	},
}

var securityAutoBlockCmd = &cobra.Command{
	Use:   "auto-block [true|false]",
	Short: "Auto-blocking",
	Long:  `Enable/disable auto-blocking`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if EnsureStandaloneMode == nil {
			cmd.PrintErrln("❌ EnsureStandaloneMode function not initialized")
			os.Exit(1)
		}
		if SyncAutoBlock == nil {
			cmd.PrintErrln("❌ SyncAutoBlock function not initialized")
			os.Exit(1)
		}
		EnsureStandaloneMode()
		enable, err := strconv.ParseBool(args[0])
		if err != nil {
			log.Fatalf("❌ Invalid boolean value: %v", err)
		}
		SyncAutoBlock(enable)
	},
}

var securityAutoBlockExpiryCmd = &cobra.Command{
	Use:   "auto-block-expiry <seconds>",
	Short: "Auto-block expiry time",
	Long:  `Set auto-block expiry time in seconds`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if EnsureStandaloneMode == nil {
			cmd.PrintErrln("❌ EnsureStandaloneMode function not initialized")
			os.Exit(1)
		}
		if SyncAutoBlockExpiry == nil {
			cmd.PrintErrln("❌ SyncAutoBlockExpiry function not initialized")
			os.Exit(1)
		}
		EnsureStandaloneMode()
		expiry, err := strconv.Atoi(args[0])
		if err != nil {
			log.Fatalf("❌ Invalid expiry value: %v", err)
		}
		SyncAutoBlockExpiry(uint32(expiry))
	},
}

func init() {
	securityCmd.AddCommand(securityFragmentsCmd)
	securityCmd.AddCommand(securityStrictTCPCmd)
	securityCmd.AddCommand(securitySYNLimitCmd)
	securityCmd.AddCommand(securityBogonCmd)
	securityCmd.AddCommand(securityAutoBlockCmd)
	securityCmd.AddCommand(securityAutoBlockExpiryCmd)

	RootCmd.AddCommand(securityCmd)
}
