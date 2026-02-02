package main

import (
	"log"
	"os"

	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/internal/xdp"
)

func runSync(args []string) {
	if len(args) < 1 {
		log.Fatal("Usage: ./netxfw sync [to-map|to-config]")
	}

	mode := args[0]
	configPath := "/etc/netxfw/config.yaml"
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// Fallback to local etc if global etc doesn't exist
		configPath = "./etc/netxfw/config.yaml"
	}

	cfg, err := types.LoadGlobalConfig(configPath)
	if err != nil {
		log.Fatalf("❌ Failed to load config: %v", err)
	}

	manager, err := xdp.NewManagerFromPins("/sys/fs/bpf/netxfw")
	if err != nil {
		log.Fatalf("❌ Failed to load pinned maps: %v", err)
	}
	defer manager.Close()

	switch mode {
	case "to-map":
		if err := manager.SyncFromFiles(cfg, false); err != nil {
			log.Fatalf("❌ Sync to map failed: %v", err)
		}
		log.Println("✅ Sync from config to BPF maps completed successfully")

	case "to-config":
		if err := manager.SyncToFiles(cfg); err != nil {
			log.Fatalf("❌ Sync to config failed: %v", err)
		}
		// Also save the updated GlobalConfig back to config.yaml
		if err := types.SaveGlobalConfig(configPath, cfg); err != nil {
			log.Fatalf("❌ Failed to save updated config to %s: %v", configPath, err)
		}
		log.Printf("✅ Sync from BPF maps to %s and %s completed successfully", configPath, cfg.Base.LockListFile)

	default:
		log.Fatalf("❌ Unknown sync mode: %s. Use 'to-map' or 'to-config'.", mode)
	}
}
