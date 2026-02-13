package main

import (
	"log"

	"github.com/livp123/netxfw/internal/core"
	"github.com/livp123/netxfw/internal/daemon"
	"github.com/livp123/netxfw/internal/runtime"
	"github.com/livp123/netxfw/internal/version"
)

func main() {
	log.Printf("Starting netxfw-dp %s (Data Plane Daemon)...", version.Version)

	// Set runtime mode
	// 设置运行模式
	runtime.Mode = "dp"

	// Initialize configuration
	// 初始化配置
	core.InitConfiguration()
	core.TestConfiguration()

	// Run the daemon logic directly
	// 直接运行守护进程逻辑
	daemon.Run(runtime.Mode)
}
