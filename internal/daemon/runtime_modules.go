package daemon

import (
	"github.com/netxfw/netxfw/internal/daemon/engine"
	"github.com/netxfw/netxfw/internal/configtypes"
	"github.com/netxfw/netxfw/pkg/sdk"
	"go.uber.org/zap"
)

// DefaultCoreModules returns the standard ordered core module set.
func DefaultCoreModules() []engine.CoreModule {
	return []engine.CoreModule{
		&engine.BaseModule{},
		&engine.ConntrackModule{},
		&engine.PortModule{},
		&engine.RateLimitModule{},
	}
}

// StartCoreModules initializes and starts the provided core modules.
func StartCoreModules(modules []engine.CoreModule, globalCfg *types.GlobalConfig, s *sdk.SDK, log *zap.SugaredLogger) error {
	for _, mod := range modules {
		if err := mod.Init(globalCfg, s, log); err != nil {
			return err
		}
		if err := mod.Start(); err != nil {
			return err
		}
	}
	return nil
}

// StartDefaultRuntimeCore bootstraps the default core module set and returns the started modules.
func StartDefaultRuntimeCore(globalCfg *types.GlobalConfig, s *sdk.SDK, log *zap.SugaredLogger) ([]engine.CoreModule, error) {
	modules := DefaultCoreModules()
	if err := StartCoreModules(modules, globalCfg, s, log); err != nil {
		return nil, err
	}
	return modules, nil
}

// ReloadCoreModules reloads the provided core modules with the new config snapshot.
func ReloadCoreModules(modules []engine.CoreModule, globalCfg *types.GlobalConfig, log *zap.SugaredLogger) {
	for _, mod := range modules {
		if err := mod.Reload(globalCfg); err != nil {
			log.Warnf("[WARN]  Failed to reload core module %s: %v", mod.Name(), err)
		}
	}
}
