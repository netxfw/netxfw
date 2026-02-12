package logger

import (
	"log"
	"os"
	"path/filepath"

	"github.com/livp123/netxfw/internal/plugins/types"
	"gopkg.in/natefinch/lumberjack.v2"
)

// Init initializes the global logger based on configuration.
func Init(cfg types.LoggingConfig) {
	if !cfg.Enabled {
		return
	}

	if cfg.Path == "" {
		log.Println("⚠️  Logging enabled but no path specified, using stdout")
		return
	}

	// Create directory if not exists
	dir := filepath.Dir(cfg.Path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		log.Printf("❌ Failed to create log directory %s: %v", dir, err)
		return
	}

	// Configure lumberjack
	rotator := &lumberjack.Logger{
		Filename:   cfg.Path,
		MaxSize:    cfg.MaxSize, // megabytes
		MaxBackups: cfg.MaxBackups,
		MaxAge:     cfg.MaxAge, // days
		Compress:   cfg.Compress,
	}

	// Set output to rotator
	log.SetOutput(rotator)
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// Log a startup message to the new file
	log.Printf("📝 Logging initialized to %s (Max: %dMB, Backups: %d, Age: %dd, Compress: %v)",
		cfg.Path, cfg.MaxSize, cfg.MaxBackups, cfg.MaxAge, cfg.Compress)
}
