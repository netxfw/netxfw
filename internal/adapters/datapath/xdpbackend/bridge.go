package xdpbackend

import (
	"time"

	"github.com/cilium/ebpf"
	backendxdp "github.com/netxfw/netxfw/internal/datapath/xdp/backend"
	"github.com/netxfw/netxfw/pkg/sdk"
	"go.uber.org/zap"
)

type Handle struct {
	inner *backendxdp.Manager
}

type Adapter struct {
	sdk.ManagerInterface
	handle *Handle
}

type InterfaceInfo struct {
	Name      string
	ProgramID uint32
	LinkID    uint32
	Mode      string
	LoadTime  time.Time
}

func NewManager(cfg sdk.CapacityConfig, log *zap.SugaredLogger) (*Handle, error) {
	manager, err := backendxdp.NewManager(cfg, log)
	if err != nil {
		return nil, err
	}
	return &Handle{inner: manager}, nil
}

func NewManagerFromPins(pinPath string, log *zap.SugaredLogger) (*Handle, error) {
	manager, err := backendxdp.NewManagerFromPins(pinPath, log)
	if err != nil {
		return nil, err
	}
	return &Handle{inner: manager}, nil
}

func NewAdapter(manager *Handle) *Adapter {
	if manager == nil || manager.inner == nil {
		return nil
	}
	return &Adapter{
		ManagerInterface: backendxdp.NewAdapter(manager.inner),
		handle:           manager,
	}
}

func (a *Adapter) GetManagerHandle() *Handle {
	if a == nil {
		return nil
	}
	return a.handle
}

func GetPhysicalInterfaces() ([]string, error) {
	return backendxdp.GetPhysicalInterfaces()
}

func GetAttachedInterfaces(pinPath string) ([]string, error) {
	return backendxdp.GetAttachedInterfaces(pinPath)
}

func GetAttachedInterfacesWithInfo(pinPath string) ([]InterfaceInfo, error) {
	infos, err := backendxdp.GetAttachedInterfacesWithInfo(pinPath)
	if err != nil {
		return nil, err
	}

	converted := make([]InterfaceInfo, 0, len(infos))
	for _, info := range infos {
		converted = append(converted, InterfaceInfo{
			Name:      info.Name,
			ProgramID: info.ProgramID,
			LinkID:    info.LinkID,
			Mode:      info.Mode,
			LoadTime:  info.LoadTime,
		})
	}
	return converted, nil
}

func (h *Handle) BackendManager() *backendxdp.Manager {
	if h == nil {
		return nil
	}
	return h.inner
}

func (h *Handle) MigrateState(old *Handle) error {
	if h == nil || h.inner == nil || old == nil || old.inner == nil {
		return nil
	}
	return h.inner.MigrateState(old.inner)
}

func (h *Handle) Close() error {
	if h == nil || h.inner == nil {
		return nil
	}
	return h.inner.Close()
}

func (h *Handle) Pin(pinPath string) error {
	return h.inner.Pin(pinPath)
}

func (h *Handle) Unpin(pinPath string) error {
	return h.inner.Unpin(pinPath)
}

func (h *Handle) Attach(interfaces []string) error {
	return h.inner.Attach(interfaces)
}

func (h *Handle) Detach(interfaces []string) error {
	return h.inner.Detach(interfaces)
}

func (h *Handle) SyncFromFiles(cfg *sdk.GlobalConfig, overwrite bool) error {
	return h.inner.SyncFromFiles(cfg, overwrite)
}

func (h *Handle) SyncToFiles(cfg *sdk.GlobalConfig) error {
	return h.inner.SyncToFiles(cfg)
}

func (h *Handle) VerifyAndRepair(cfg *sdk.GlobalConfig) error {
	return h.inner.VerifyAndRepair(cfg)
}

func (h *Handle) LockList() *ebpf.Map {
	return h.inner.LockList()
}

func (h *Handle) DynLockList() *ebpf.Map {
	return h.inner.DynLockList()
}

func (h *Handle) Whitelist() *ebpf.Map {
	return h.inner.Whitelist()
}

func (h *Handle) IPPortRules() *ebpf.Map {
	return h.inner.IPPortRules()
}

func (h *Handle) MatchesCapacity(cfg sdk.CapacityConfig) bool {
	return h.inner.MatchesCapacity(cfg)
}

func (h *Handle) XDPProgram() *ebpf.Program {
	return h.inner.XdpFirewall()
}

func (h *Handle) LoadPlugin(path string, index int) error {
	return h.inner.LoadPlugin(path, index)
}

func (h *Handle) RemovePlugin(index int) error {
	return h.inner.RemovePlugin(index)
}

func (h *Handle) LookupPluginProgram(index int) (uint32, bool, error) {
	var progID uint32
	if err := h.inner.JmpTable().Lookup(uint32(index), &progID); err != nil {
		return 0, false, err
	}
	return progID, true, nil
}

func (h *Handle) PerfStats() any {
	return h.inner.PerfStats()
}
