package plugins

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	datapathprograms "github.com/netxfw/netxfw/internal/datapath/xdp/programs"
	domaindatapath "github.com/netxfw/netxfw/internal/domain/plugin/datapath"
	"github.com/netxfw/netxfw/internal/utils/logger"
)

// validatePluginPath 验证插件路径是否安全
func validatePluginPath(path string, allowedDirs []string) error {
	if path == "" {
		return fmt.Errorf("plugin path is required")
	}

	// 清理路径
	cleanPath := filepath.Clean(path)

	// 检查是否为绝对路径
	if !filepath.IsAbs(cleanPath) {
		return fmt.Errorf("plugin path must be absolute")
	}

	// 检查是否在允许的目录内
	allowed := false
	for _, dir := range allowedDirs {
		if strings.HasPrefix(cleanPath, dir) {
			allowed = true
			break
		}
	}

	if !allowed {
		return fmt.Errorf("plugin path must be in allowed directories: %v", allowedDirs)
	}

	// 检查文件是否存在
	if _, err := os.Stat(cleanPath); os.IsNotExist(err) {
		return fmt.Errorf("plugin file does not exist")
	}

	// 检查文件权限
	info, err := os.Stat(cleanPath)
	if err != nil {
		return err
	}

	// 检查是否为普通文件
	if !info.Mode().IsRegular() {
		return fmt.Errorf("plugin path is not a regular file")
	}

	// 检查是否可执行
	if info.Mode()&0111 == 0 {
		return fmt.Errorf("plugin file is not executable")
	}

	return nil
}

// ExecutePinned runs a datapath plugin lifecycle command against the pinned manager.
func ExecutePinned(ctx context.Context, pinPath string, cmd domaindatapath.Command) error {
	log := logger.Get(ctx)

	manager, err := datapathprograms.OpenPinnedManager(pinPath, log)
	if err != nil {
		return fmt.Errorf("failed to load XDP manager: %v (Is the firewall running?)", err)
	}
	defer manager.Close()

	switch cmd.Action {
	case "load":
		if err := Load(manager, cmd.Path, cmd.Index); err != nil {
			return fmt.Errorf("failed to load plugin: %v", err)
		}
	case "remove":
		if err := Remove(manager, cmd.Index); err != nil {
			return fmt.Errorf("failed to remove plugin: %v", err)
		}
	default:
		return fmt.Errorf("unknown plugin command: %s", cmd.Action)
	}

	log.Infof("[OK] Datapath plugin command %s executed successfully", cmd.Action)
	return nil
}

// ListPinned returns the current datapath plugin slots from the pinned manager.
func ListPinned(ctx context.Context, pinPath string) ([]domaindatapath.SlotStatus, error) {
	log := logger.Get(ctx)

	manager, err := datapathprograms.OpenPinnedManager(pinPath, log)
	if err != nil {
		return nil, fmt.Errorf("failed to load XDP manager: %v (Is the firewall running?)", err)
	}
	defer manager.Close()

	return ListSlots(manager)
}
