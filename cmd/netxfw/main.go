package main

import (
	"fmt"

	"github.com/livp123/netxfw/cmd/netxfw/commands"
	"github.com/livp123/netxfw/cmd/netxfw/commands/common"
	"github.com/livp123/netxfw/internal/core"
	"github.com/livp123/netxfw/internal/version"
)

/**
 * isIPv6 checks if the given IP string (or CIDR) is IPv6.
 * isIPv6 检查给定的 IP 字符串（或 CIDR）是否为 IPv6。
 */
// func isIPv6(ipStr string) bool {
// 	return core.IsIPv6(ipStr)
// }

func main() {
	// Initialize command functions
	initializeCommandFunctions()

	// Execute Cobra commands
	commands.Execute()
}

func initializeCommandFunctions() {
	// System commands
	common.InitConfiguration = core.InitConfiguration
	common.ShowStatus = core.ShowStatus
	common.ShowTopStats = core.ShowTopStats
	common.TestConfiguration = core.TestConfiguration
	common.RunDaemon = core.RunDaemon
	common.InstallXDP = core.InstallXDP
	common.ReloadXDP = core.ReloadXDP
	common.RemoveXDP = core.RemoveXDP
	common.SyncDefaultDeny = core.SyncDefaultDeny
	common.SyncEnableRateLimit = core.SyncEnableRateLimit
	common.SyncEnableAFXDP = core.SyncEnableAFXDP

	// Rule commands
	common.EnsureStandaloneMode = ensureStandaloneMode
	common.SyncLockMap = core.SyncLockMap
	common.SyncWhitelistMap = core.SyncWhitelistMap
	common.SyncIPPortRule = core.SyncIPPortRule
	common.ShowIPPortRules = core.ShowIPPortRules
	common.ShowWhitelist = core.ShowWhitelist
	common.ShowLockList = core.ShowLockList
	common.ImportLockListFromFile = core.ImportLockListFromFile
	common.ImportWhitelistFromFile = core.ImportWhitelistFromFile
	common.ImportIPPortRulesFromFile = core.ImportIPPortRulesFromFile
	common.ClearBlacklist = core.ClearBlacklist

	// Security commands
	common.SyncDropFragments = core.SyncDropFragments
	common.SyncStrictTCP = core.SyncStrictTCP
	common.SyncSYNLimit = core.SyncSYNLimit
	common.SyncBogonFilter = core.SyncBogonFilter
	common.SyncAutoBlock = core.SyncAutoBlock
	common.SyncAutoBlockExpiry = core.SyncAutoBlockExpiry

	// Limit commands
	common.SyncRateLimitRule = core.SyncRateLimitRule
	common.ShowRateLimitRules = core.ShowRateLimitRules

	// Port commands
	common.SyncAllowedPort = core.SyncAllowedPort

	// Web commands
	common.RunWebServer = core.RunWebServer

	// Conntrack commands
	common.ShowConntrack = core.ShowConntrack

	// Quick commands
	common.AskConfirmation = core.AskConfirmation
}

/**
 * askConfirmation asks the user for a y/n confirmation.
 */
func askConfirmation(prompt string) bool {
	return core.AskConfirmation(prompt)
}

/**
 * printUsage prints command line help.
 * printUsage 打印命令行帮助信息。
 */
func printUsage() {
	fmt.Println("Usage: ./netxfw [command]")
	fmt.Println("\nAvailable Commands:")
	fmt.Println("  system      System management commands")
	fmt.Println("  rule        Manage firewall rules")
	fmt.Println("  security    Security management commands")
	fmt.Println("  limit       Rate limit management")
	fmt.Println("  port        Port management")
	fmt.Println("  web         Start web management interface")
	fmt.Println("  conntrack   Show active connections")
	fmt.Println("  lock        Quickly block IP")
	fmt.Println("  unlock      Quickly unblock IP")
	fmt.Println("  allow       Quickly whitelist IP")
	fmt.Println("  unallow     Quickly remove from whitelist")
	fmt.Println("  clear       Quickly clear blacklist")
	fmt.Println("  version     Show version information")
	fmt.Println("\nUse './netxfw [command] --help' for more information about a command.")
}

func showVersion() {
	fmt.Printf("netxfw %s\n", version.Version)
	core.ShowStatus() // showStatus now includes edition info
}

func ensureStandaloneMode() {
	// Check if we're running in standalone mode (not as daemon)
	// For standalone mode, we just ensure that we can access the BPF maps
	// This function can be expanded based on specific requirements
}
