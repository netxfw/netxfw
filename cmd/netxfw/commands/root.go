package commands

import (
	"fmt"
	"os"

	"github.com/livp123/netxfw/cmd/netxfw/commands/agent"
	"github.com/livp123/netxfw/cmd/netxfw/commands/dp"
	"github.com/livp123/netxfw/internal/runtime"
	"github.com/spf13/cobra"
)

var RootCmd = &cobra.Command{
	Use:   "netxfw",
	Short: "A high-performance eBPF/XDP based firewall",
	Long: `netxfw is a high-performance firewall built on eBPF/XDP technology.
It provides stateful packet filtering, connection tracking, and rate limiting.`,
}

func init() {
	RootCmd.PersistentFlags().StringVar(&runtime.Mode, "mode", "", "Operation mode: dp (Data Plane) or agent (Control Plane)")

	// Register Agent commands
	RootCmd.AddCommand(agent.RuleCmd)
	RootCmd.AddCommand(agent.LimitCmd)
	RootCmd.AddCommand(agent.SecurityCmd)
	RootCmd.AddCommand(agent.PortCmd)
	RootCmd.AddCommand(agent.WebCmd)
	RootCmd.AddCommand(agent.QuickBlockCmd)
	RootCmd.AddCommand(agent.QuickUnlockCmd)
	RootCmd.AddCommand(agent.QuickAllowCmd)
	RootCmd.AddCommand(agent.QuickUnallowCmd)
	RootCmd.AddCommand(agent.QuickClearCmd)
	RootCmd.AddCommand(agent.SystemCmd)
	RootCmd.AddCommand(agent.VersionCmd)

	// Register DP commands
	RootCmd.AddCommand(dp.ConntrackCmd)
}

func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
