package daemon

import (
	"context"
	"fmt"

	appconfig "github.com/netxfw/netxfw/internal/app/config"
	"github.com/netxfw/netxfw/internal/config"
	"github.com/netxfw/netxfw/internal/utils/logger"
	"github.com/netxfw/netxfw/internal/datapath/xdp/backend"
	"github.com/netxfw/netxfw/pkg/sdk"
	"go.uber.org/zap"
)

// LoadRuntimeConfigSnapshot reloads the current config snapshot and ensures it is non-nil.
func LoadRuntimeConfigSnapshot() (*sdk.GlobalConfig, error) {
	globalCfg, err := config.ReloadCurrentConfig()
	if err != nil {
		return nil, err
	}
	if globalCfg == nil {
		return nil, fmt.Errorf("config is nil after loading")
	}
	return globalCfg, nil
}

// InitRuntimeLogging initializes logging and optional pprof from config.
func InitRuntimeLogging(globalCfg *sdk.GlobalConfig) {
	logger.Init(globalCfg.Logging)
	if globalCfg.Base.EnablePprof {
		startPprof(globalCfg.Base.PprofPort)
	}
}

// VerifyRuntimeConfigAndMaps preserves the current startup verify-and-repair behavior.
func VerifyRuntimeConfigAndMaps(manager interface {
	VerifyAndRepair(*sdk.GlobalConfig) error
}, globalCfg *sdk.GlobalConfig, log *zap.SugaredLogger) {
	switch m := manager.(type) {
	case *xdp.Manager:
		adapter := xdp.NewAdapter(m)
		if _, err := appconfig.VerifyAndRepair(context.Background(), adapter, globalCfg); err != nil {
			log.Warnf("[WARN]  Startup consistency check failed: %v", err)
		} else {
			log.Info("[OK] Startup consistency check passed (Config synced to BPF).")
		}
		return
	case *xdp.Adapter:
		if _, err := appconfig.VerifyAndRepair(context.Background(), m, globalCfg); err != nil {
			log.Warnf("[WARN]  Startup consistency check failed: %v", err)
		} else {
			log.Info("[OK] Startup consistency check passed (Config synced to BPF).")
		}
		return
	}

	if err := manager.VerifyAndRepair(globalCfg); err != nil {
		log.Warnf("[WARN]  Startup consistency check failed: %v", err)
	} else {
		log.Info("[OK] Startup consistency check passed (Config synced to BPF).")
	}
}

// RequirePinnedManager loads an already pinned manager and wraps it as an adapter.
func RequirePinnedManager(pinPath string, log *zap.SugaredLogger) (sdkManager *xdp.Adapter, realMgr *xdp.Manager, err error) {
	realMgr, err = xdp.NewManagerFromPins(pinPath, log)
	if err != nil {
		return nil, nil, err
	}
	return xdp.NewAdapter(realMgr), realMgr, nil
}
