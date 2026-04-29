package daemon

import (
	"context"
	"fmt"

	appconfig "github.com/netxfw/netxfw/internal/app/config"
	datapathprograms "github.com/netxfw/netxfw/internal/datapath/xdp/programs"
	"github.com/netxfw/netxfw/internal/ports"
	"github.com/netxfw/netxfw/internal/utils/logger"
	sdk "github.com/netxfw/netxfw/pkg/sdk"
	"go.uber.org/zap"
)

// LoadRuntimeConfigSnapshot reloads the current config snapshot and ensures it is non-nil.
func LoadRuntimeConfigSnapshot() (*sdk.GlobalConfig, error) {
	globalCfg, err := appconfig.LoadConfig()
	if err != nil {
		return nil, err
	}
	if globalCfg == nil {
		return nil, fmt.Errorf("config is nil after loading")
	}
	return ports.ConfigToSDK(globalCfg), nil
}

// InitRuntimeLogging initializes logging and optional pprof from config.
func InitRuntimeLogging(globalCfg *sdk.GlobalConfig) {
	logger.Init(globalCfg.Logging)
	if globalCfg.Base.EnablePprof {
		startPprofOn(globalCfg.Base.PprofBind, globalCfg.Base.PprofPort)
	}
}

// VerifyRuntimeConfigAndMaps preserves the current startup verify-and-repair behavior.
func VerifyRuntimeConfigAndMaps(manager interface {
	VerifyAndRepair(*sdk.GlobalConfig) error
}, globalCfg *sdk.GlobalConfig, log *zap.SugaredLogger) {
	switch m := manager.(type) {
	case *datapathprograms.Handle:
		adapter := datapathprograms.NewAdapter(m)
		reconciler := ports.SDKConfigReconcilerAdapter{ManagerInterface: adapter}
		if _, err := appconfig.VerifyAndRepair(context.Background(), reconciler, ports.ConfigFromSDK(globalCfg)); err != nil {
			log.Warnf("[WARN]  Startup consistency check failed: %v", err)
		} else {
			log.Info("[OK] Startup consistency check passed (Config synced to BPF).")
		}
		return
	case sdk.ManagerInterface:
		reconciler := ports.SDKConfigReconcilerAdapter{ManagerInterface: m}
		if _, err := appconfig.VerifyAndRepair(context.Background(), reconciler, ports.ConfigFromSDK(globalCfg)); err != nil {
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
func RequirePinnedManager(pinPath string, log *zap.SugaredLogger) (sdkManager sdk.ManagerInterface, realMgr *datapathprograms.Handle, err error) {
	realMgr, err = datapathprograms.OpenPinnedManager(pinPath, log)
	if err != nil {
		return nil, nil, err
	}
	return datapathprograms.NewAdapter(realMgr), realMgr, nil
}
