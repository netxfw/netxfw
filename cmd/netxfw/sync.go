package main

import (
	"log"

	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/internal/xdp"
)

func runSync() {
	configPath := "/etc/netxfw/config.yaml"
	cfg, err := types.LoadGlobalConfig(configPath)
	if err != nil {
		log.Fatalf("❌ Failed to load config: %v", err)
	}

	manager, err := xdp.NewManagerFromPins("/sys/fs/bpf/netxfw")
	if err != nil {
		log.Fatalf("❌ Failed to load pinned maps: %v", err)
	}
	defer manager.Close()

	if err := manager.SyncFromFiles(cfg, false); err != nil {
		log.Fatalf("❌ Sync failed: %v", err)
	}

	log.Println("✅ Sync completed successfully")
}
