package app

import (
	"context"
	"fmt"

	"github.com/netxfw/netxfw/internal/api"
	"github.com/netxfw/netxfw/internal/daemon"
	datapathlifecycle "github.com/netxfw/netxfw/internal/datapath/xdp/lifecycle"
	datapathplugins "github.com/netxfw/netxfw/internal/datapath/xdp/plugins"
	datapathprograms "github.com/netxfw/netxfw/internal/datapath/xdp/programs"
	"github.com/netxfw/netxfw/internal/utils/logger"
	"github.com/netxfw/netxfw/pkg/sdk"
	"go.uber.org/zap"
)

// IsXDPLoaded returns true if XDP is attached to any interface.
func IsXDPLoaded() bool {
	ifaces, err := datapathprograms.GetAttachedInterfaces(GetPinPath())
	return err == nil && len(ifaces) > 0
}

/**
 * InstallXDP initializes the XDP manager and mounts the program to interfaces, then exits.
 * InstallXDP 初始化 XDP 管理器并将程序挂载到接口，然后退出。
 *
 * 功能说明 / Function Description:
 * 1. 加载全局配置文件 / Load global configuration file
 * 2. 解析网络接口 / Resolve network interfaces
 * 3. 创建 XDP 管理器 / Create XDP manager
 * 4. 固定 BPF maps 到文件系统 / Pin BPF maps to filesystem
 * 5. 同步配置和规则到 BPF maps / Sync configuration and rules to BPF maps
 * 6. 挂载 XDP 程序到网络接口 / Attach XDP program to network interfaces
 * 7. 初始化并启动核心模块 / Initialize and start core modules
 * 8. 初始化并启动插件 / Initialize and start plugins
 *
 * 参数 / Parameters:
 * - ctx: 上下文 / Context
 * - cliInterfaces: 命令行指定的接口列表，为空则使用配置文件 / CLI specified interfaces, use config if empty
 *
 * 返回值 / Returns:
 * - error: 错误信息 / Error message
 */
func InstallXDP(ctx context.Context, cliInterfaces []string) error {
	log := logger.Get(ctx)

	globalCfg, err := LoadConfig()
	if err != nil {
		return fmt.Errorf("failed to load global config: %v", err)
	}
	if globalCfg == nil {
		return fmt.Errorf("config is nil after loading")
	}

	result, err := datapathlifecycle.Install(ctx, GetPinPath(), cliInterfaces, globalCfg, log)
	if err != nil {
		return err
	}
	manager := result.Manager

	err = loadBPFPlugins(manager, globalCfg, log)
	if err != nil {
		log.Warnf("[WARN]  Failed to load BPF plugins: %v (continuing anyway)", err)
	}

	s := sdk.NewSDK(datapathprograms.NewAdapter(manager))
	webHost := api.NewServer(s, globalCfg.Web.Port)
	_, err = daemon.StartDefaultRuntimeCore(globalCfg, s, log)
	if err != nil {
		return fmt.Errorf("[ERROR] %v", err)
	}
	_, _ = daemon.StartRuntimePlugins(ctx, nil, nil, globalCfg, log, s, webHost)

	log.Infof("[START] XDP program installed successfully and pinned to %s", GetPinPath())
	return nil
}

// loadBPFPlugins loads BPF plugins configured in the global config.
// loadBPFPlugins 加载全局配置中配置的 BPF 插件。
func loadBPFPlugins(manager interface {
	LoadPlugin(path string, index int) error
	RemovePlugin(index int) error
}, globalCfg *sdk.GlobalConfig, log *zap.SugaredLogger) error {
	return datapathplugins.LoadConfigured(manager, globalCfg, log)
}

// ValidateAndAttachXDP validates the requested attach mode and attaches XDP.
func ValidateAndAttachXDP(ctx context.Context, interfaces []string, mode string) ([]string, error) {
	switch mode {
	case "offload", "drv", "skb":
		return AttachXDPWithMode(ctx, interfaces, mode)
	default:
		return nil, fmt.Errorf("invalid mode. must be one of: offload, drv, skb")
	}
}

/**
 * RemoveXDP detaches the XDP program from all interfaces and unpins everything.
 * RemoveXDP 从所有接口分离 XDP 程序并取消所有固定。
 */
func RemoveXDP(ctx context.Context, cliInterfaces []string) error {
	globalCfg, err := LoadConfig()
	if err != nil {
		logger.Get(ctx).Warnf("[WARN]  Failed to load global config, using default map capacity: %v", err)
		globalCfg = &sdk.GlobalConfig{}
	}
	return datapathlifecycle.Remove(ctx, GetPinPath(), cliInterfaces, globalCfg)
}

func ReloadXDP(ctx context.Context, cliInterfaces []string) error {
	globalCfg, err := LoadConfig()
	if err != nil {
		return fmt.Errorf("failed to load global config: %v", err)
	}
	return datapathlifecycle.Reload(ctx, GetPinPath(), cliInterfaces, globalCfg)
}

/**
 * RunWebServer starts the API and UI server.
 * RunWebServer 启动 API 和 UI 服务器。
 */
func AttachXDPWithMode(ctx context.Context, interfaces []string, mode string) ([]string, error) {
	globalCfg, err := LoadConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}
	if globalCfg == nil {
		return nil, fmt.Errorf("config is nil after loading")
	}

	return datapathlifecycle.AttachWithMode(ctx, GetPinPath(), interfaces, mode, globalCfg, logger.Get(ctx))
}

/**
 * UnloadXDP provides instructions to unload the program.
 * UnloadXDP 提供卸载程序的指令。
 */
func UnloadXDP() {
	datapathlifecycle.UnloadInstructions()
}
