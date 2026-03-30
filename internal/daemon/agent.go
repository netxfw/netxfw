package daemon

import (
	"context"

	"github.com/netxfw/netxfw/internal/config"
	"github.com/netxfw/netxfw/internal/utils/logger"
	"github.com/netxfw/netxfw/internal/xdp"
	"github.com/netxfw/netxfw/pkg/sdk"
)

// runControlPlane handles API, Web, Log Engine, and high-level management.
// runControlPlane 处理 API、Web、日志引擎和高级管理。
func runControlPlane(ctx context.Context, opts *DaemonOptions) {
	log := logger.Get(ctx)
	configPath := config.GetConfigPath()
	pidPath := config.DefaultPidPath

	log.Info("[START] Starting netxfw in Agent (Control Plane) mode")

	// Use the interfaces from options if provided
	// 如果提供了选项中的接口，则使用它们
	var interfaces []string
	if opts != nil {
		interfaces = opts.Interfaces
	}

	if err := managePidFileWithInterfaces(pidPath, interfaces); err != nil {
		log.Fatalf("[ERROR] %v", err)
	}
	defer removePidFileWithInterfaces(pidPath, interfaces)

	globalCfg, err := LoadRuntimeConfigSnapshot()
	if err != nil {
		log.Errorf("[ERROR] Failed to load global config from %s: %v", configPath, err)
		return
	}

	// Initialize Logging / 初始化日志
	InitRuntimeLogging(globalCfg)

	// 1. Initialize Manager
	var manager xdp.ManagerInterface
	if opts != nil && opts.Manager != nil {
		log.Info("Using injected Manager (e.g. for testing)")
		manager = opts.Manager
	} else {
		pinPath := config.GetPinPath()
		adapter, realMgr, err := RequirePinnedManager(pinPath, log)
		if err != nil {
			log.Errorf("[ERROR] Agent requires netxfw daemon to be running and maps pinned at %s: %v", pinPath, err)
			return
		}
		defer realMgr.Close()
		manager = adapter
	}

	// Consistency Check at startup (Ensure BPF maps match Config)
	// 启动时的一致性检查（确保 BPF Map 与配置匹配）
	VerifyRuntimeConfigAndMaps(manager, globalCfg, log)

	// 2. Load ALL Plugins (Agent manages everything) / 加载所有插件（Agent 管理一切）
	var fw sdk.Firewall
	if adapter, ok := manager.(sdk.Firewall); ok {
		fw = adapter
	}

	s := sdk.NewSDK(manager)
	pluginCtx := BuildPluginContext(ctx, fw, manager, globalCfg, log, s)
	startedPlugins := StartPlugins(pluginCtx, log)
	defer StopPlugins(startedPlugins)

	// 4. Start Cleanup Loop / 启动清理循环
	ctxCleanup, cancel := context.WithCancel(ctx)
	defer cancel()
	go runCleanupLoop(ctxCleanup, globalCfg)

	// 5. Start Traffic Stats Loop / 启动流量统计循环
	go runTrafficStatsLoop(ctxCleanup, s)

	log.Info("[SHIELD] Agent is running.")
	waitForSignal(ctx, configPath, s, nil, nil) // nil means reload all / nil 表示重新加载所有内容
}
