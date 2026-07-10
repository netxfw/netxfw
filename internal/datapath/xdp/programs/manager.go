package programs

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	backendxdp "github.com/netxfw/netxfw/internal/datapath/xdp/backend"
	sdk "github.com/netxfw/netxfw/pkg/sdk"
	"go.uber.org/zap"
)

type PerformanceStats = backendxdp.PerformanceStats

type InterfaceInfo = backendxdp.InterfaceXDPInfo

// Handle wraps the current datapath manager implementation behind the programs facade.
type Handle struct {
	manager *backendxdp.Manager
}

// OpenPinnedManager loads a manager from the currently pinned datapath maps.
func OpenPinnedManager(pinPath string, log *zap.SugaredLogger) (*Handle, error) {
	manager, err := backendxdp.NewManagerFromPins(pinPath, log)
	if err != nil {
		return nil, err
	}
	return &Handle{manager: manager}, nil
}

// CreateManager creates a new datapath manager for the provided capacity config.
func CreateManager(capacity sdk.CapacityConfig, log *zap.SugaredLogger) (*Handle, error) {
	manager, err := backendxdp.NewManager(capacity, log)
	if err != nil {
		return nil, fmt.Errorf("failed to create XDP manager: %v", err)
	}
	return &Handle{manager: manager}, nil
}

// WrapExisting wraps an already-created backend manager into the programs facade.
func WrapExisting(manager *backendxdp.Manager) *Handle {
	if manager == nil {
		return nil
	}
	return &Handle{manager: manager}
}

// NewAdapter wraps a datapath manager into the SDK-facing adapter.
func NewAdapter(manager *Handle) sdk.ManagerInterface {
	if manager == nil {
		return nil
	}
	return backendxdp.NewAdapter(manager.manager)
}

// GetPhysicalInterfaces returns all physical network interfaces eligible for XDP.
func GetPhysicalInterfaces() ([]string, error) {
	return backendxdp.GetPhysicalInterfaces()
}

// GetAttachedInterfaces returns interface names with pinned XDP attachments.
func GetAttachedInterfaces(pinPath string) ([]string, error) {
	return backendxdp.GetAttachedInterfaces(pinPath)
}

// GetAttachedInterfacesWithInfo returns detailed XDP attachment information.
func GetAttachedInterfacesWithInfo(pinPath string) ([]InterfaceInfo, error) {
	return backendxdp.GetAttachedInterfacesWithInfo(pinPath)
}

// NewMetricsCollector constructs a metrics collector for the wrapped manager.
func NewMetricsCollector(handle *Handle) *backendxdp.MetricsCollector {
	if handle == nil {
		return nil
	}
	return backendxdp.NewMetricsCollector(handle.manager)
}

// NewStatsCache constructs a stats cache for the wrapped manager.
func NewStatsCache(handle *Handle) *backendxdp.StatsCache {
	if handle == nil {
		return nil
	}
	return backendxdp.NewStatsCache(handle.manager)
}

// NewHealthChecker constructs a health checker for the wrapped manager.
func NewHealthChecker(handle *Handle) *backendxdp.HealthChecker {
	if handle == nil {
		return nil
	}
	return backendxdp.NewHealthChecker(handle.manager)
}

// NewIncrementalUpdater constructs an incremental updater for the wrapped manager.
func NewIncrementalUpdater(handle *Handle) *backendxdp.IncrementalUpdater {
	if handle == nil {
		return nil
	}
	return backendxdp.NewIncrementalUpdater(handle.manager)
}

// MigrateState copies runtime state from old manager into new manager.
func MigrateState(newHandle, oldHandle *Handle) error {
	if newHandle == nil || oldHandle == nil {
		return nil
	}
	return newHandle.manager.MigrateState(oldHandle.manager)
}

// Close releases manager resources.
func (h *Handle) Close() error {
	if h == nil || h.manager == nil {
		return nil
	}
	return h.manager.Close()
}

// Pin persists manager maps under the provided pin path.
func (h *Handle) Pin(pinPath string) error {
	return h.manager.Pin(pinPath)
}

// Unpin removes persisted manager maps from the provided pin path.
func (h *Handle) Unpin(pinPath string) error {
	return h.manager.Unpin(pinPath)
}

// Attach attaches the XDP program to the provided interfaces.
func (h *Handle) Attach(interfaces []string) error {
	return h.manager.Attach(interfaces)
}

// Detach detaches the XDP program from the provided interfaces.
func (h *Handle) Detach(interfaces []string) error {
	return h.manager.Detach(interfaces)
}

// SyncFromFiles syncs config and persisted rules into runtime maps.
func (h *Handle) SyncFromFiles(cfg *sdk.GlobalConfig, overwrite bool) error {
	return h.manager.SyncFromFiles(cfg, overwrite)
}

// SyncToFiles syncs runtime state back into config structures.
func (h *Handle) SyncToFiles(cfg *sdk.GlobalConfig) error {
	return h.manager.SyncToFiles(cfg)
}

// VerifyAndRepair reconciles runtime state against config through the wrapped manager.
func (h *Handle) VerifyAndRepair(cfg *sdk.GlobalConfig) error {
	return h.manager.VerifyAndRepair(cfg)
}

// StaticBlacklist returns the static blacklist map.
func (h *Handle) StaticBlacklist() *ebpf.Map {
	return h.manager.StaticBlacklist()
}

// DynamicBlacklist returns the dynamic blacklist map.
func (h *Handle) DynamicBlacklist() *ebpf.Map {
	return h.manager.DynamicBlacklist()
}

// Whitelist returns the whitelist map.
func (h *Handle) Whitelist() *ebpf.Map {
	return h.manager.Whitelist()
}

// RuleMap returns the active unified rule map.
func (h *Handle) RuleMap() *ebpf.Map {
	return h.manager.RuleMap()
}

// MatchesCapacity reports whether the current manager capacity matches cfg.
func (h *Handle) MatchesCapacity(cfg sdk.CapacityConfig) bool {
	return h.manager.MatchesCapacity(cfg)
}

// GetWhitelistCount returns the number of whitelist entries.
func (h *Handle) GetWhitelistCount() (uint64, error) {
	return h.manager.GetWhitelistCount()
}

// GetRuleMapCount returns the number of rule map entries.
func (h *Handle) GetRuleMapCount() (uint64, error) {
	return h.manager.GetRuleMapCount()
}

// XDPProgram returns the main XDP program handle.
func (h *Handle) XDPProgram() *ebpf.Program {
	return h.manager.XdpFirewall()
}

// LoadPlugin inserts a datapath plugin into the jump table.
func (h *Handle) LoadPlugin(path string, index int) error {
	return h.manager.LoadPlugin(path, index)
}

// RemovePlugin removes a datapath plugin from the jump table.
func (h *Handle) RemovePlugin(index int) error {
	return h.manager.RemovePlugin(index)
}

// LookupPluginProgram returns the program id currently stored in the jump table slot.
func (h *Handle) LookupPluginProgram(index int) (uint32, bool, error) {
	var progID uint32
	if err := h.manager.JmpTable().Lookup(uint32(index), &progID); err != nil {
		return 0, false, err
	}
	return progID, true, nil
}

// PerfStats returns the raw performance statistics handle.
func (h *Handle) PerfStats() any {
	if h == nil || h.manager == nil {
		return nil
	}
	return h.manager.PerfStats()
}

// AttachProgram attaches the provided XDP program using explicit link options.
func AttachProgram(program *ebpf.Program, ifaceIndex int, flags link.XDPAttachFlags) (link.Link, error) {
	return link.AttachXDP(link.XDPOptions{
		Program:   program,
		Interface: ifaceIndex,
		Flags:     flags,
	})
}
