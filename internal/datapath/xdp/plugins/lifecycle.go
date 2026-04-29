package plugins

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	datapathprograms "github.com/netxfw/netxfw/internal/datapath/xdp/programs"
	domaindatapath "github.com/netxfw/netxfw/internal/domain/plugin/datapath"
	"github.com/netxfw/netxfw/internal/utils/logger"
)

// validatePluginPath 验证插件路径是否安全
func validatePluginPath(path string, allowedDirs []string) error {
	if path == "" {
		return fmt.Errorf("plugin path is required")
	}

	cleanPath := filepath.Clean(path)

	// 检查是否为绝对路径
	if !filepath.IsAbs(cleanPath) {
		return fmt.Errorf("plugin path must be absolute")
	}

	// 检查是否在允许的目录内
	allowed := false
	for _, dir := range allowedDirs {
		cleanDir := filepath.Clean(dir) + string(os.PathSeparator)
		if strings.HasPrefix(cleanPath, cleanDir) {
			allowed = true
			break
		}
	}

	if !allowed {
		return fmt.Errorf("plugin path must be in allowed directories: %v", allowedDirs)
	}

	if _, err := os.Lstat(cleanPath); os.IsNotExist(err) {
		return fmt.Errorf("plugin file does not exist")
	}

	info, err := os.Lstat(cleanPath)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("plugin path must not be a symlink")
	}

	// 检查是否为普通文件
	if !info.Mode().IsRegular() {
		return fmt.Errorf("plugin path is not a regular file")
	}

	if info.Mode()&0111 == 0 {
		return fmt.Errorf("plugin file is not executable")
	}
	if info.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("plugin file must not be group/world-writable")
	}
	if runtime.GOOS == "linux" {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("plugin owner information unavailable")
		}
		if stat.Uid != 0 {
			return fmt.Errorf("plugin file must be owned by root")
		}
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
