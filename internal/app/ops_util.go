package app

import (
	"context"
	"fmt"

	"github.com/netxfw/netxfw/internal/binary"
	"github.com/netxfw/netxfw/internal/config"
	"github.com/netxfw/netxfw/internal/utils/fileutil"
	"github.com/netxfw/netxfw/internal/utils/fmtutil"
	"github.com/netxfw/netxfw/internal/utils/iputil"
	"github.com/netxfw/netxfw/internal/utils/logger"
	"github.com/netxfw/netxfw/internal/version"
	"github.com/netxfw/netxfw/internal/xdp"
)

// TrafficStats is the app-layer alias for shared runtime traffic statistics.
type TrafficStats = xdp.TrafficStats

// PerformanceStats is the app-layer alias for performance statistics.
type PerformanceStats = xdp.PerformanceStats

// OperationStats is the app-layer alias for per-operation stats.
type OperationStats = xdp.OperationStats

// BinaryRecord is the app-layer alias for binary import/export records.
type BinaryRecord = binary.Record

// PluginSlot describes a loaded BPF plugin slot.
type PluginSlot struct {
	Index   int
	Program uint32
}

// GetAttachedInterfaceInfos returns detailed XDP attachment information.
func GetAttachedInterfaceInfos() ([]xdp.InterfaceXDPInfo, error) {
	return xdp.GetAttachedInterfacesWithInfo(GetPinPath())
}

// LogInfo writes an info log message using the logger stored in context.
func LogInfo(ctx context.Context, format string, args ...any) {
	logger.Get(ctx).Infof(format, args...)
}

// Version returns the current application version string.
func Version() string {
	return version.Version
}

// RunShellPipeline executes a trusted shell pipeline command.
func RunShellPipeline(command string) error {
	return fmtutil.RunShellPipeline(command)
}

// RemoveLineFromFile removes an exact line from a file.
func RemoveLineFromFile(filePath, line string) error {
	return fileutil.RemoveFromFile(filePath, line)
}

// ParseIPPort parses an input string like 1.2.3.4:80 or [::1]:80 into IP/CIDR and port.
func ParseIPPort(input string) (string, uint16, error) {
	return iputil.ParseIPPort(input)
}

// IsValidIP reports whether s is a valid IP address.
func IsValidIP(s string) bool {
	return iputil.IsValidIP(s)
}

// IsValidCIDR reports whether s is a valid IP or CIDR string.
func IsValidCIDR(s string) bool {
	return iputil.IsValidCIDR(s)
}

// NormalizeCIDR ensures the IP string is in canonical CIDR format when possible.
func NormalizeCIDR(ipStr string) string {
	return iputil.NormalizeCIDR(ipStr)
}

// GetBackupKeep returns the active backup retention policy.
func GetBackupKeep() int {
	return config.GetBackupKeep()
}

// RunDeployUpdate executes the trusted deployment update pipeline.
func RunDeployUpdate() error {
	execCmd := "curl -sSL https://raw.githubusercontent.com/netxfw/netxfw/main/scripts/deploy.sh | bash"
	return RunShellPipeline(execCmd)
}

// ReloadXDP performs a hot-reload of the XDP program.
// It loads new objects, migrates state from old pinned maps, and swaps the program.
// ReloadXDP 执行 XDP 程序的平滑重载：加载新对象，从旧的固定 Map 迁移状态，并切换程序。
func ReloadPinnedMaps(ctx context.Context) error {
	globalCfg, err := LoadConfig()
	if err != nil {
		return fmt.Errorf("failed to load global config: %v", err)
	}
	if globalCfg == nil {
		return fmt.Errorf("config is nil after loading")
	}

	log := logger.Get(ctx)
	manager, err := xdp.NewManagerFromPins(GetPinPath(), log)
	if err != nil {
		return fmt.Errorf("failed to load XDP manager: %v", err)
	}
	defer manager.Close()

	if err := manager.SyncFromFiles(globalCfg, false); err != nil {
		return fmt.Errorf("failed to sync configuration to BPF maps: %v", err)
	}

	return nil
}
