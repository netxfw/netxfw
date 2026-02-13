package core

import (
	"fmt"
	"net"
	"strings"
)

/**
 * IsIPv6 checks if the given IP string (or CIDR) is IPv6.
 * IsIPv6 检查给定的 IP 字符串（或 CIDR）是否为 IPv6。
 */
func IsIPv6(ipStr string) bool {
	ip, _, err := net.ParseCIDR(ipStr)
	if err != nil {
		ip = net.ParseIP(ipStr)
	}
	return ip != nil && ip.To4() == nil
}

/**
 * AskConfirmation asks the user for a y/n confirmation.
 * AskConfirmation 询问用户是否确认 (y/n)。
 */
func AskConfirmation(prompt string) bool {
	fmt.Printf("%s [y/N]: ", prompt)
	var response string
	_, err := fmt.Scanln(&response)
	if err != nil {
		return false
	}
	response = strings.ToLower(strings.TrimSpace(response))
	return response == "y" || response == "yes"
}
