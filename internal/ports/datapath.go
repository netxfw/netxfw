package ports

import (
	"github.com/cilium/ebpf"
	domainconfig "github.com/netxfw/netxfw/internal/domain/config"
	sdk "github.com/netxfw/netxfw/pkg/sdk"
)

// RuntimeStateReader exposes the subset of runtime manager reads needed by app/domain projections.
type RuntimeStateReader interface {
	GlobalConfig() *ebpf.Map
	StaticBlacklist() *ebpf.Map
	DynamicBlacklist() *ebpf.Map
	Whitelist() *ebpf.Map
	RuleMap() *ebpf.Map
	RatelimitMap() *ebpf.Map
	ConntrackMap() *ebpf.Map
	GetLockedIPCount() (int, error)
	GetWhitelistCount() (int, error)
	GetConntrackCount() (int, error)
	GetDynLockListCount() (uint64, error)
	ListAllowedPorts() ([]uint16, error)
	ListIPPortRules(withCounters bool, limit int, search string) ([]sdk.IPPortRule, int, error)
	ListRateLimitRules(limit int, search string) (map[string]sdk.RateLimitConf, int, error)
}

// DatapathManager exposes the app-facing datapath reconciliation boundary.
type DatapathManager interface {
	Attach([]string) error
	Detach([]string) error
	SyncFromConfig(*domainconfig.Config, bool) error
	SyncToConfig(*domainconfig.Config) error
	VerifyAndRepair(*domainconfig.Config) error
}

// DatapathSyncer captures the sync/repair subset used by config reconciliation.
type DatapathSyncer interface {
	SyncFromFiles(cfg *domainconfig.Config, overwrite bool) error
	SyncToFiles(cfg *domainconfig.Config) error
	VerifyAndRepair(cfg *domainconfig.Config) error
}

// ConfigReconciler captures the combined sync/read surface needed by config reconciliation.
type ConfigReconciler interface {
	DatapathSyncer
	RuntimeStateReader
}

// DatapathPluginLoader captures plugin load/remove operations used during startup.
type DatapathPluginLoader interface {
	LoadPlugin(path string, index int) error
	RemovePlugin(index int) error
}
