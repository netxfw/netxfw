package mcp

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/internal/xdp"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

type MCPServer struct {
	manager    *xdp.Manager
	server     *server.MCPServer
	configPath string
	token      string
}

func NewMCPServer(manager *xdp.Manager) *MCPServer {
	s := server.NewMCPServer(
		"netxfw-ai-expert",
		"1.0.0",
		server.WithResourceCapabilities(true, true),
		server.WithLogging(),
	)

	ms := &MCPServer {
		manager:    manager,
		server:     s,
		configPath: "/etc/netxfw/config.yaml",
	}

	ms.registerTools()
	return ms
}

func (s *MCPServer) SetToken(token string) {
	s.token = token
}

func (s *MCPServer) GetOrGenerateToken() string {
	if s.token != "" {
		return s.token
	}

	// Try to load from config
	cfg, err := types.LoadGlobalConfig(s.configPath)
	if err == nil && cfg.MCP.Token != "" {
		s.token = cfg.MCP.Token
		return s.token
	}

	// Generate random token if not found
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		log.Printf("❌ Failed to generate random token: %v", err)
		return ""
	}
	s.token = hex.EncodeToString(b)

	// Persist to config
	if err == nil {
		cfg.MCP.Token = s.token
		if cfg.MCP.Port == 0 {
			cfg.MCP.Port = 11812
		}
		if err := types.SaveGlobalConfig(s.configPath, cfg); err == nil {
			log.Printf("📄 Persisted new MCP token to %s", s.configPath)
		}
	}

	return s.token
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

	// Persistence logic
	globalCfg, err := types.LoadGlobalConfig(s.configPath)
	if err == nil && globalCfg.Base.PersistRules {
		if action == "deny" {
			filePath := globalCfg.Base.LockListFile
			if filePath != "" {
				// Check if already in file
				found := false
				if f, err := os.Open(filePath); err == nil {
					scanner := bufio.NewScanner(f)
					for scanner.Scan() {
						if strings.TrimSpace(scanner.Text()) == cidr {
							found = true
							break
						}
					}
					f.Close()
				}

				if !found {
					f, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
					if err == nil {
						if _, err := f.WriteString(cidr + "\n"); err == nil {
							log.Printf("📄 Persisted %s to %s", cidr, filePath)
						}
						f.Close()
					}
				}
			}
		} else {
			// Whitelist persistence
			entry := cidr
			if port > 0 {
				entry = fmt.Sprintf("%s:%d", cidr, port)
			}
			found := false
			for _, ip := range globalCfg.Base.Whitelist {
				if ip == entry {
					found = true
					break
				}
			}
			if !found {
				globalCfg.Base.Whitelist = append(globalCfg.Base.Whitelist, entry)
				if err := types.SaveGlobalConfig(s.configPath, globalCfg); err == nil {
					log.Printf("📄 Persisted whitelist entry %s to %s", entry, s.configPath)
				}
			}
		}
	}

	return mcp.NewToolResultText(fmt.Sprintf("Successfully added %s rule for %s (port: %d)", action, cidr, port)), nil
}

func (s *MCPServer) ServeSSE(addr string) error {
	// Create SSE server with options
	sseServer := server.NewSSEServer(s.server,
		server.WithBaseURL("http://"+addr),
	)

	// Auth middleware
	authMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if s.token != "" {
				// Check Authorization header: Bearer <token>
				authHeader := r.Header.Get("Authorization")
				if authHeader == "" {
					// Also check query parameter: ?token=<token>
					authHeader = r.URL.Query().Get("token")
					if authHeader != "" {
						authHeader = "Bearer " + authHeader
					}
				}

				if authHeader != "Bearer "+s.token {
					http.Error(w, "Unauthorized: Invalid or missing token", http.StatusUnauthorized)
					log.Printf("⚠️ Unauthorized access attempt from %s", r.RemoteAddr)
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}

	// Register handlers with auth
	http.Handle("/sse", authMiddleware(sseServer.SSEHandler()))
	http.Handle("/message", authMiddleware(sseServer.MessageHandler()))

	log.Printf("🤖 netxfw AI MCP Server starting (SSE mode) on %s", addr)
	if s.token != "" {
		log.Printf("🔑 Security: Token authentication enabled")
	} else {
		log.Printf("⚠️ Security: No token set, server is public!")
	}
	log.Printf("🔗 SSE Endpoint: http://%s/sse", addr)
	return http.ListenAndServe(addr, nil)
}

func (s *MCPServer) Serve() error {
	return server.ServeStdio(s.server)
}
