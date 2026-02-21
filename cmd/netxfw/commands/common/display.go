package common

import (
	"context"
	"fmt"
	"strings"

	"github.com/netxfw/netxfw/pkg/sdk"
)

// ShowConntrack reads and prints all active connections.
// ShowConntrack 读取并打印所有活动连接。
func ShowConntrack(ctx context.Context, s *sdk.SDK) error {
	entries, err := s.Conntrack.List()
	if err != nil {
		return fmt.Errorf("failed to list conntrack entries: %v", err)
	}

	fmt.Println("🕵️  Active Connections (Conntrack):")
	if len(entries) == 0 {
		fmt.Println(" - No active connections.")
		return nil
	}

	fmt.Printf("%-40s %-5s %-40s %-5s %-8s\n", "Source", "Port", "Destination", "Port", "Protocol")
	fmt.Println(strings.Repeat("-", 110))

	// Sort entries for better display / 排序条目以获得更好的显示效果
	for _, e := range entries {
		proto := fmt.Sprintf("%d", e.Protocol)
		if e.Protocol == 6 {
			proto = "TCP"
		} else if e.Protocol == 17 {
			proto = "UDP"
		} else if e.Protocol == 1 {
			proto = "ICMP"
		} else if e.Protocol == 58 {
			proto = "ICMPv6"
		}
		fmt.Printf("%-40s %-5d %-40s %-5d %-8s\n", e.SrcIP, e.SrcPort, e.DstIP, e.DstPort, proto)
	}
	fmt.Printf("\nTotal active connections: %d\n", len(entries))
	return nil
}
