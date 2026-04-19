package app

import (
	"context"
	"fmt"
	"io"

	appconfig "github.com/netxfw/netxfw/internal/app/config"
	netxfw_binary "github.com/netxfw/netxfw/internal/binary"
	"github.com/netxfw/netxfw/internal/optimizer"
	"github.com/netxfw/netxfw/internal/runtime"
	"github.com/netxfw/netxfw/internal/utils/logger"
	"github.com/netxfw/netxfw/pkg/sdk"
)

// GetDefaultConfigPath returns the preferred default configuration path.
func GetDefaultConfigPath() string {
	return appconfig.GetDefaultConfigPath()
}

// DefaultConfigTemplate returns the default TOML config template text.
func DefaultConfigTemplate() string {
	return appconfig.DefaultConfigTemplate()
}

// RuntimeConfigPathVar returns a pointer to the runtime config path string for flag binding.
func RuntimeConfigPathVar() *string {
	return &runtime.ConfigPath
}

// SetConfigPath updates the active configuration path.
func SetConfigPath(path string) {
	appconfig.SetConfigPath(path)
}

// ReinitLoggerFromConfig reloads config and re-initializes logging.
func ReinitLoggerFromConfig(ctx context.Context) context.Context {
	cfg, err := LoadConfig()
	if err != nil || cfg == nil {
		return ctx
	}

	logger.Init(cfg.Logging)
	ctx = logger.WithContext(ctx, logger.Get(nil))
	logger.Get(ctx).Infof("Logging re-initialized from config")
	return ctx
}

// GetConfigPath returns the active configuration file path.
func GetConfigPath() string {
	return appconfig.GetConfigPath()
}

// LoadConfig loads the current configuration using the configured path.
func LoadConfig() (*sdk.GlobalConfig, error) {
	return appconfig.LoadConfig()
}

// MutateLoadedConfig reloads the current configuration, applies fn, and persists it.
func MutateLoadedConfig(fn func(*sdk.GlobalConfig) error) error {
	return appconfig.MutateLoadedConfig(fn)
}

// OptimizeWhitelistConfig normalizes and merges whitelist entries in config.
func OptimizeWhitelistConfig(cfg *sdk.GlobalConfig) {
	optimizer.OptimizeWhitelistConfig(cfg)
}

// OptimizeIPPortRulesConfig normalizes and merges IP+Port rules in config.
func OptimizeIPPortRulesConfig(cfg *sdk.GlobalConfig) {
	optimizer.OptimizeIPPortRulesConfig(cfg)
}

// PersistWhitelistEntry records a whitelist entry in config if needed.
func PersistWhitelistEntry(ip string, port uint16) error {
	if IsTestMode() {
		return nil
	}

	return MutateLoadedConfig(func(globalCfg *sdk.GlobalConfig) error {
		normalizedCIDR := NormalizeCIDR(ip)
		entry := normalizedCIDR
		if port > 0 {
			entry = fmt.Sprintf("%s:%d", normalizedCIDR, port)
		}

		for _, existing := range globalCfg.Base.Whitelist {
			host, existingPort, parseErr := ParseIPPort(existing)
			existingCIDR := ""
			if parseErr == nil {
				existingCIDR = NormalizeCIDR(host)
			} else {
				existingCIDR = NormalizeCIDR(existing)
				existingPort = 0
			}

			if existingCIDR == normalizedCIDR && existingPort == port {
				return nil
			}
		}

		globalCfg.Base.Whitelist = append(globalCfg.Base.Whitelist, entry)
		OptimizeWhitelistConfig(globalCfg)
		return nil
	})
}

// PersistIPPortRule records an IP+Port rule in config if needed.
func PersistIPPortRule(ip string, port uint16, action uint8) error {
	if IsTestMode() {
		return nil
	}

	return MutateLoadedConfig(func(globalCfg *sdk.GlobalConfig) error {
		normalizedCIDR := NormalizeCIDR(ip)
		updated := false

		for i := range globalCfg.Port.IPPortRules {
			ruleCIDR := NormalizeCIDR(globalCfg.Port.IPPortRules[i].IP)
			if ruleCIDR == normalizedCIDR && globalCfg.Port.IPPortRules[i].Port == port {
				globalCfg.Port.IPPortRules[i].Action = action
				updated = true
				break
			}
		}

		if !updated {
			globalCfg.Port.IPPortRules = append(globalCfg.Port.IPPortRules, sdk.IPPortRule{
				IP:     normalizedCIDR,
				Port:   port,
				Action: action,
			})
		}

		OptimizeIPPortRulesConfig(globalCfg)
		return nil
	})
}

// DecodeBinaryRecords decodes binary rule records from a reader.
func DecodeBinaryRecords(r io.Reader) ([]BinaryRecord, error) {
	return netxfw_binary.Decode(r)
}

// EncodeBinaryRecords encodes binary rule records to a writer.
func EncodeBinaryRecords(w io.Writer, records []BinaryRecord) error {
	return netxfw_binary.Encode(w, records)
}

// WithConfigLock runs fn while holding the shared config persistence mutex.
func WithConfigLock(fn func() error) error {
	return fn()
}

// ReconcileConfigToRuntime applies the active config to runtime through the unified reconcile entry.
func ReconcileConfigToRuntime(ctx context.Context, mgr sdk.ManagerInterface, cfg *sdk.GlobalConfig) error {
	_, err := appconfig.ReconcileConfigToRuntime(ctx, mgr, cfg)
	return err
}

// ReconcileRuntimeToConfig captures runtime state back into config through the unified reconcile entry.
func ReconcileRuntimeToConfig(ctx context.Context, mgr sdk.ManagerInterface, cfg *sdk.GlobalConfig) error {
	_, err := appconfig.ReconcileRuntimeToConfig(ctx, mgr, cfg)
	return err
}

// VerifyAndRepairRuntime checks drift and reconciles runtime using the unified reconcile entry.
func VerifyAndRepairRuntime(ctx context.Context, mgr sdk.ManagerInterface, cfg *sdk.GlobalConfig) error {
	_, err := appconfig.VerifyAndRepair(ctx, mgr, cfg)
	return err
}
