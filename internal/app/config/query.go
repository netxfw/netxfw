package config

import (
	"fmt"
	"sync"

	"github.com/netxfw/netxfw/internal/adapters/configfile"
	domainconfig "github.com/netxfw/netxfw/internal/domain/config"
	runtimestate "github.com/netxfw/netxfw/internal/domain/runtime"
	systemstate "github.com/netxfw/netxfw/internal/domain/system"
	"github.com/netxfw/netxfw/internal/ports"
	"github.com/netxfw/netxfw/internal/runtime"
)

type StatusSnapshot struct {
	Config  *domainconfig.Config
	Desired systemstate.DesiredState
	Actual  runtimestate.ActualState
	Drift   runtimestate.StateDiff
}

type managerProvider interface {
	GetManager() ports.RuntimeStateReader
}

const (
	defaultConfigPath = "/etc/netxfw/config.toml"
	defaultBackupKeep = 3
)

var configFileMu sync.RWMutex

func GetDefaultConfigPath() string {
	return defaultConfigPath
}

func SetConfigPath(path string) {
	runtime.ConfigPath = path
}

func GetConfigPath() string {
	if runtime.ConfigPath != "" {
		return runtime.ConfigPath
	}
	return GetDefaultConfigPath()
}

func LoadConfig() (*domainconfig.Config, error) {
	configFileMu.RLock()
	defer configFileMu.RUnlock()

	cfg, err := configfile.Load(GetConfigPath())
	if err != nil {
		return nil, fmt.Errorf("failed to load configuration: %w", err)
	}
	return cfg, nil
}

func MutateLoadedConfig(fn func(*domainconfig.Config) error) error {
	configFileMu.Lock()
	defer configFileMu.Unlock()

	cfg, err := configfile.Load(GetConfigPath())
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}
	if cfg == nil {
		return fmt.Errorf("config is nil")
	}
	if err := fn(cfg); err != nil {
		return err
	}

	backupKeep := defaultBackupKeep
	if cfg.Base.BackupKeep > 0 {
		backupKeep = cfg.Base.BackupKeep
	}
	return configfile.SaveWithBackup(GetConfigPath(), cfg, backupKeep)
}

func GetBackupKeep() int {
	cfg, err := LoadConfig()
	if err == nil && cfg != nil && cfg.Base.BackupKeep > 0 {
		return cfg.Base.BackupKeep
	}
	return defaultBackupKeep
}

func DefaultConfigTemplate() string {
	return configfile.DefaultTemplate()
}

func extractManager(source any) ports.RuntimeStateReader {
	switch typed := source.(type) {
	case nil:
		return nil
	case ports.RuntimeStateReader:
		return typed
	case managerProvider:
		return typed.GetManager()
	default:
		return nil
	}
}

func LoadStatusSnapshot(source any) (StatusSnapshot, error) {
	cfg, err := LoadConfig()
	if err != nil {
		return StatusSnapshot{}, err
	}

	mgr := extractManager(source)
	desired := systemstate.FromConfig(cfg)
	actual := runtimestate.FromManager(mgr)

	return StatusSnapshot{
		Config:  cfg,
		Desired: desired,
		Actual:  actual,
		Drift:   runtimestate.CompareDesired(desired, actual),
	}, nil
}

func GetConntrackMax() int {
	cfg, err := LoadConfig()
	if err == nil && cfg != nil && cfg.Capacity.Conntrack > 0 {
		return cfg.Capacity.Conntrack
	}
	return 100000
}
