package mcp

import (
	"context"
	"fmt"

	"github.com/livp123/netxfw/internal/xdp"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

type MCPServer struct {
	manager *xdp.Manager
	server  *server.MCPServer
}

func NewMCPServer(manager *xdp.Manager) *MCPServer {
	s := server.NewMCPServer(
		"netxfw-ai-expert",
		"1.0.0",
		server.WithResourceCapabilities(true, true),
		server.WithLogging(),
	)

	ms := &MCPServer{
		manager: manager,
		server:  s,
	}

	ms.registerTools()
	return ms
}

func (s *MCPServer) registerTools() {
	// Tool: get_stats
	s.server.AddTool(mcp.NewTool("get_stats",
		mcp.WithDescription("Get real-time packet filtering statistics (pass/drop counts) from netxfw."),
	), s.handleGetStats)

	// Tool: list_conntrack
	s.server.AddTool(mcp.NewTool("list_conntrack",
		mcp.WithDescription("List active network connections tracked by the firewall."),
	), s.handleListConntrack)

	// Tool: add_rule
	s.server.AddTool(mcp.NewTool("add_rule",
		mcp.WithDescription("Add a new firewall rule to block or allow traffic."),
		mcp.WithString("cidr", mcp.Description("IP or CIDR range (e.g. 1.2.3.4 or 192.168.1.0/24)"), mcp.Required()),
		mcp.WithNumber("port", mcp.Description("Optional port number (0 for all ports)")),
		mcp.WithString("action", mcp.Description("Action to take (allow/deny)"), mcp.Required()),
	), s.handleAddRule)
}

func (s *MCPServer) handleGetStats(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	pass, drop := s.manager.GetStats()
	return mcp.NewToolResultText(fmt.Sprintf("Current Statistics:\n- Passed Packets: %d\n- Dropped Packets: %d", pass, drop)), nil
}

func (s *MCPServer) handleListConntrack(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	entries, err := s.manager.ListConntrackEntries()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to list conntrack: %v", err)), nil
	}

	if len(entries) == 0 {
		return mcp.NewToolResultText("No active connections found."), nil
	}

	limit := 10
	if len(entries) > limit {
		entries = entries[:limit]
	}

	res := fmt.Sprintf("Active Connections (Top %d of %d):\n", len(entries), len(entries))
	for _, e := range entries {
		proto := "TCP"
		if e.Protocol == 17 {
			proto = "UDP"
		}
		res += fmt.Sprintf("- %s:%d -> %s:%d (%s)\n", e.SrcIP, e.SrcPort, e.DstIP, e.DstPort, proto)
	}
	return mcp.NewToolResultText(res), nil
}

func (s *MCPServer) handleAddRule(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	cidr, err := request.RequireString("cidr")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Missing cidr: %v", err)), nil
	}
	action, err := request.RequireString("action")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Missing action: %v", err)), nil
	}
	port := uint16(request.GetFloat("port", 0))

	var opErr error
	if action == "deny" {
		if xdp.IsIPv6(cidr) {
			opErr = xdp.LockIP(s.manager.LockList6(), cidr)
		} else {
			opErr = xdp.LockIP(s.manager.LockList(), cidr)
		}
	} else {
		if xdp.IsIPv6(cidr) {
			opErr = xdp.AllowIP(s.manager.Whitelist6(), cidr, port)
		} else {
			opErr = xdp.AllowIP(s.manager.Whitelist(), cidr, port)
		}
	}

	if opErr != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to add rule: %v", opErr)), nil
	}

	return mcp.NewToolResultText(fmt.Sprintf("Successfully added %s rule for %s (port: %d)", action, cidr, port)), nil
}

func (s *MCPServer) Serve() error {
	return server.ServeStdio(s.server)
}
