package main

import (
	"fmt"
	"net"
	"strings"

	"github.com/livp123/netxfw/cmd/netxfw/commands"
	"github.com/livp123/netxfw/internal/version"
)

/**
 * isIPv6 checks if the given IP string (or CIDR) is IPv6.
 * isIPv6 检查给定的 IP 字符串（或 CIDR）是否为 IPv6。
 */
func isIPv6(ipStr string) bool {
	ip, _, err := net.ParseCIDR(ipStr)
	if err != nil {
		ip = net.ParseIP(ipStr)
	}
	return ip != nil && ip.To4() == nil
}

func main() {
	// Initialize command functions
	initializeCommandFunctions()

	// Execute Cobra commands
	commands.Execute()
}

func initializeCommandFunctions() {
	// System commands
	commands.InitConfiguration = initConfiguration
	commands.ShowStatus = showStatus
	commands.TestConfiguration = testConfiguration
	commands.RunDaemon = runDaemon
	commands.InstallXDP = installXDP
	commands.ReloadXDP = reloadXDP
	commands.RemoveXDP = removeXDP
	commands.SyncDefaultDeny = syncDefaultDeny
	commands.SyncEnableRateLimit = syncEnableRateLimit
	commands.SyncEnableAFXDP = syncEnableAFXDP

	// Rule commands
	commands.EnsureStandaloneMode = ensureStandaloneMode
	commands.SyncLockMap = syncLockMap
	commands.SyncWhitelistMap = syncWhitelistMap
	commands.SyncIPPortRule = syncIPPortRule
	commands.ShowIPPortRules = showIPPortRules
	commands.ShowWhitelist = showWhitelist
	commands.ShowLockList = showLockList
	commands.ImportLockListFromFile = importLockListFromFile
	commands.ImportWhitelistFromFile = importWhitelistFromFile
	commands.ImportIPPortRulesFromFile = importIPPortRulesFromFile
	commands.ClearBlacklist = clearBlacklist

	// Security commands
	commands.SyncDropFragments = syncDropFragments
	commands.SyncStrictTCP = syncStrictTCP
	commands.SyncSYNLimit = syncSYNLimit
	commands.SyncBogonFilter = syncBogonFilter
	commands.SyncAutoBlock = syncAutoBlock
	commands.SyncAutoBlockExpiry = syncAutoBlockExpiry

	// Limit commands
	commands.SyncRateLimitRule = syncRateLimitRule
	commands.ShowRateLimitRules = showRateLimitRules

	// Port commands
	commands.SyncAllowedPort = syncAllowedPort

	// Web commands
	commands.RunWebServer = runWebServer

	// Conntrack commands
	commands.ShowConntrack = showConntrack

	// Quick commands
	commands.AskConfirmation = askConfirmation
}

/**
 * askConfirmation asks the user for a y/n confirmation.
 */
func askConfirmation(prompt string) bool {
	fmt.Printf("%s [y/N]: ", prompt)
	var response string
	_, err := fmt.Scanln(&response)
	if err != nil {
		return false
	}
	response = strings.ToLower(strings.TrimSpace(response))
	return response == "y" || response == "yes"
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
	showStatus() // showStatus now includes edition info
}

func ensureStandaloneMode() {
	// Check if we're running in standalone mode (not as daemon)
	// For standalone mode, we just ensure that we can access the BPF maps
	// This function can be expanded based on specific requirements
}
