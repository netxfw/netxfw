package logger

import (
	"log"
	"os"
	"path/filepath"

	"github.com/livp123/netxfw/internal/plugins/types"
	"gopkg.in/natefinch/lumberjack.v2"
)

// Init initializes the global logger based on configuration.
// Init 根据配置初始化全局日志记录器。
func Init(cfg types.LoggingConfig) {
	if !cfg.Enabled {
		return
	}

	if cfg.Path == "" {
		log.Println("⚠️  Logging enabled but no path specified, using stdout / 日志已启用但未指定路径，使用标准输出")
		return
	}

	// Create directory if not exists / 如果目录不存在则创建
	dir := filepath.Dir(cfg.Path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		log.Printf("❌ Failed to create log directory %s: %v / 创建日志目录 %s 失败：%v", dir, err, dir, err)
		return
	}

	// Configure lumberjack / 配置 lumberjack
	rotator := &lumberjack.Logger{
		Filename:   cfg.Path,
		MaxSize:    cfg.MaxSize, // megabytes / 兆字节
		MaxBackups: cfg.MaxBackups,
		MaxAge:     cfg.MaxAge, // days / 天数
		Compress:   cfg.Compress,
	}

	// Set output to rotator / 设置输出到 rotator
	log.SetOutput(rotator)
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// Log a startup message to the new file / 将启动消息记录到新文件
	log.Printf("📝 Logging initialized to %s (Max: %dMB, Backups: %d, Age: %dd, Compress: %v) / 日志已初始化到 %s",
		cfg.Path, cfg.MaxSize, cfg.MaxBackups, cfg.MaxAge, cfg.Compress, cfg.Path)
}
