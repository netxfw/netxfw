package core

import (
	"context"
	"fmt"

	"github.com/netxfw/netxfw/internal/config"
	"github.com/netxfw/netxfw/internal/plugins/types"
	"github.com/netxfw/netxfw/internal/utils/logger"
)

// SyncToConfig dumps current BPF map states to configuration files.
// This is useful if the config files were lost or if changes were made directly to maps.
// SyncToConfig 将当前 BPF Map 状态转储到配置文件。
// 如果配置文件丢失或直接对 Map 进行了更改，此功能非常有用。
func SyncToConfig(ctx context.Context, mgr XDPManager) error {
	log := logger.Get(ctx)
	log.Info("🔄 Syncing BPF Maps to Configuration Files...")

	types.ConfigMu.Lock()
	defer types.ConfigMu.Unlock()

	// Use the config manager to load the configuration
	cfgManager := config.GetConfigManager()
	err := cfgManager.LoadConfig()
	if err != nil {
		return fmt.Errorf("failed to load config: %v", err)
	}

	globalCfg := cfgManager.GetConfig()
	if globalCfg == nil {
		return fmt.Errorf("config is nil after loading")
	}

	// Use XDP Manager's SyncToFiles implementation to ensure consistency
	// 使用 XDP 管理器的 SyncToFiles 实现以确保一致性
	if err := mgr.SyncToFiles(globalCfg); err != nil {
		return fmt.Errorf("failed to sync maps to files: %v", err)
	}

	// Update config in manager and save using the manager
	cfgManager.UpdateConfig(globalCfg)
	if err := cfgManager.SaveConfig(); err != nil {
		return fmt.Errorf("failed to save config: %v", err)
	}
	log.Info("✅ Configuration files updated successfully.")
	return nil
}

// SyncToMap applies the current configuration files to the BPF maps.
// This overwrites the runtime state with what is in the files.
// SyncToMap 将当前配置文件应用到 BPF Map。
// 这会用文件中的内容覆盖运行时状态。
func SyncToMap(ctx context.Context, mgr XDPManager) error {
	log := logger.Get(ctx)
	log.Info("🔄 Syncing Configuration Files to BPF Maps...")

	types.ConfigMu.Lock()
	// Use the config manager to load the configuration
	cfgManager := config.GetConfigManager()
	err := cfgManager.LoadConfig()
	types.ConfigMu.Unlock() // Unlock after reading, SyncFromFiles might take time but maps are safe

	if err != nil {
		return fmt.Errorf("failed to load config: %v", err)
	}

	globalCfg := cfgManager.GetConfig()
	if globalCfg == nil {
		return fmt.Errorf("config is nil after loading")
	}

	// Use XDP Manager's SyncFromFiles implementation
	// 使用 XDP 管理器的 SyncFromFiles 实现
	if err := mgr.SyncFromFiles(globalCfg, true); err != nil {
		return fmt.Errorf("failed to sync files to maps: %v", err)
	}

	log.Info("✅ BPF Maps synced from configuration.")
	return nil
}
