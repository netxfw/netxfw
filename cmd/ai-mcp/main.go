package main

import (
	"log"
	"os"

	"github.com/livp123/netxfw/internal/mcp"
	"github.com/livp123/netxfw/internal/xdp"
)

func main() {
	// AI MCP Server typically interacts with a running instance via pinned maps
	// AI MCP Server 通常通过固定（pinned）的 Map 与运行中的实例交互
	pinPath := "/sys/fs/bpf/netxfw"
	
	if _, err := os.Stat(pinPath); os.IsNotExist(err) {
		log.Fatalf("❌ Error: netxfw is not running or BPF maps are not pinned at %s. Please run 'netxfw load xdp' first.", pinPath)
	}

	manager, err := xdp.NewManagerFromPins(pinPath)
	if err != nil {
		log.Fatalf("❌ Failed to initialize manager from pins: %v", err)
	}

	server := mcp.NewMCPServer(manager)
	
	log.Printf("🤖 netxfw AI MCP Server starting (stdio mode)...")
	if err := server.Serve(); err != nil {
		log.Fatalf("❌ MCP Server error: %v", err)
	}
}
