package ports

import (
	"os"

	"github.com/netxfw/netxfw/internal/plugins/types"
	"github.com/netxfw/netxfw/internal/xdp"
)

// ConfigGateway is the single write entry for persisted config/state.
type ConfigGateway interface {
	WriteFile(path string, data []byte, perm os.FileMode, source string) error
	SaveGlobalConfig(path string, cfg *types.GlobalConfig, keepBackups int, source string) error
}

// RuleStore defines persistence operations for rule snapshots.
type RuleStore interface {
	Export(path string, data []byte, format string) error
}

// XDPPort defines runtime control entry points used by application services.
type XDPPort interface {
	Install(interfaces []string) error
	Remove(interfaces []string) error
	Reload(interfaces []string) error
	Manager() *xdp.Manager
}

// PluginPort defines lifecycle hooks for plugin runtime orchestration.
type PluginPort interface {
	Init() error
	Start() error
	Reload() error
	Stop() error
}
