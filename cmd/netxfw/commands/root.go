package commands

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var RootCmd = &cobra.Command{
	Use:   "netxfw",
	Short: "A high-performance eBPF/XDP based firewall",
	Long: `netxfw is a high-performance firewall built on eBPF/XDP technology.
It provides stateful packet filtering, connection tracking, and rate limiting.`,
}

func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
