package main

import (
	"context"

	"github.com/netxfw/netxfw/internal/config"
	"github.com/netxfw/netxfw/internal/core"
	"github.com/netxfw/netxfw/internal/daemon"
	"github.com/netxfw/netxfw/internal/plugins/types"
	"github.com/netxfw/netxfw/internal/runtime"
	"github.com/netxfw/netxfw/internal/utils/logger"
	"github.com/netxfw/netxfw/internal/version"
)

func main() {
	// Initialize logger with defaults (stdout) / 使用默认值初始化日志记录器（标准输出）
	logger.Init(logger.LoggingConfig{Enabled: true, Level: "info"})
	defer logger.Sync()

	l := logger.Get(nil)
	l.Infof("Starting netxfw-dp %s (Data Plane Daemon)...", version.Version)

	// Set runtime mode / 设置运行模式
	runtime.Mode = "dp"
	ctx := context.Background()
	ctx = logger.WithContext(ctx, l)

	// Initialize configuration / 初始化配置
	core.InitConfiguration(ctx)
	daemon.TestConfiguration(ctx)

	// Re-initialize logger from config / 从配置重新初始化日志记录器
	cfg, err := types.LoadGlobalConfig(config.GetConfigPath())
	if err == nil {
		logger.Init(cfg.Logging)
		// Update context with new logger instance / 使用新的日志记录器实例更新上下文
		ctx = logger.WithContext(ctx, logger.Get(nil))
		logger.Get(ctx).Infof("Logging re-initialized from config")
	}

	// Run the daemon logic directly / 直接运行守护进程逻辑
	daemon.Run(ctx, runtime.Mode, nil)
}
