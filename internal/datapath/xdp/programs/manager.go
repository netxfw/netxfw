package programs

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	xdpbackend "github.com/netxfw/netxfw/internal/adapters/datapath/xdpbackend"
	healthbridge "github.com/netxfw/netxfw/internal/adapters/datapath/xdpbackend/healthbridge"
	statsbridge "github.com/netxfw/netxfw/internal/adapters/datapath/xdpbackend/statsbridge"
	syncbridge "github.com/netxfw/netxfw/internal/adapters/datapath/xdpbackend/syncbridge"
	"github.com/netxfw/netxfw/pkg/sdk"
	"go.uber.org/zap"
)

type PerformanceStats = statsbridge.PerformanceStats

// Handle wraps the current datapath manager implementation behind the programs facade.
type Handle struct {
	manager *xdpbackend.Handle
}

// OpenPinnedManager loads a manager from the currently pinned datapath maps.
func OpenPinnedManager(pinPath string, log *zap.SugaredLogger) (*Handle, error) {
	manager, err := xdpbackend.NewManagerFromPins(pinPath, log)
	if err != nil {
		return nil, err
	}
	return &Handle{manager: manager}, nil
}

// CreateManager creates a new datapath manager for the provided capacity config.
func CreateManager(capacity sdk.CapacityConfig, log *zap.SugaredLogger) (*Handle, error) {
	manager, err := xdpbackend.NewManager(capacity, log)
	if err != nil {
		return nil, fmt.Errorf("failed to create XDP manager: %v", err)
	}
	return &Handle{manager: manager}, nil
}

// WrapExisting bridges an already-created backend manager into the programs facade.
func WrapExisting(manager *xdpbackend.Handle) *Handle {
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
	return xdpbackend.NewAdapter(manager.manager)
}

// GetPhysicalInterfaces returns all physical network interfaces eligible for XDP.
func GetPhysicalInterfaces() ([]string, error) {
	return xdpbackend.GetPhysicalInterfaces()
}

// GetAttachedInterfaces returns interface names with pinned XDP attachments.
func GetAttachedInterfaces(pinPath string) ([]string, error) {
	return xdpbackend.GetAttachedInterfaces(pinPath)
}

// GetAttachedInterfacesWithInfo returns detailed XDP attachment information.
func GetAttachedInterfacesWithInfo(pinPath string) ([]xdpbackend.InterfaceInfo, error) {
	return xdpbackend.GetAttachedInterfacesWithInfo(pinPath)
}

// NewMetricsCollector constructs a metrics collector for the wrapped manager.
func NewMetricsCollector(handle *Handle) *statsbridge.Collector {
	if handle == nil {
		return nil
	}
	return statsbridge.NewMetricsCollector(handle.manager)
}

// NewStatsCache constructs a stats cache for the wrapped manager.
func NewStatsCache(handle *Handle) *statsbridge.Cache {
	if handle == nil {
		return nil
	}
	return statsbridge.NewStatsCache(handle.manager)
}

// NewHealthChecker constructs a health checker for the wrapped manager.
func NewHealthChecker(handle *Handle) *healthbridge.Checker {
	if handle == nil {
		return nil
	}
	return healthbridge.NewHealthChecker(handle.manager)
}

// NewIncrementalUpdater constructs an incremental updater for the wrapped manager.
func NewIncrementalUpdater(handle *Handle) *syncbridge.Updater {
	if handle == nil {
		return nil
	}
	return syncbridge.NewIncrementalUpdater(handle.manager)
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

// LockList returns the static blacklist map.
func (h *Handle) LockList() *ebpf.Map {
	return h.manager.LockList()
}

// DynLockList returns the dynamic blacklist map.
func (h *Handle) DynLockList() *ebpf.Map {
	return h.manager.DynLockList()
}

// Whitelist returns the whitelist map.
func (h *Handle) Whitelist() *ebpf.Map {
	return h.manager.Whitelist()
}

// IPPortRules returns the IP-port rule map.
func (h *Handle) IPPortRules() *ebpf.Map {
	return h.manager.IPPortRules()
}

// MatchesCapacity reports whether the current manager capacity matches cfg.
func (h *Handle) MatchesCapacity(cfg sdk.CapacityConfig) bool {
	return h.manager.MatchesCapacity(cfg)
}

// XDPProgram returns the main XDP program handle.
func (h *Handle) XDPProgram() *ebpf.Program {
	return h.manager.XDPProgram()
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
	return h.manager.LookupPluginProgram(index)
}

// PerfStats returns the raw performance statistics handle.
func (h *Handle) PerfStats() any {
	return h.manager.PerfStats()
}

// SDKManager returns an SDK-facing manager adapter.
func (h *Handle) SDKManager() sdk.ManagerInterface {
	return NewAdapter(h)
}

// AttachProgram attaches the provided XDP program using explicit link options.
func AttachProgram(program *ebpf.Program, ifaceIndex int, flags link.XDPAttachFlags) (link.Link, error) {
	return link.AttachXDP(link.XDPOptions{
		Program:   program,
		Interface: ifaceIndex,
		Flags:     flags,
	})
}
