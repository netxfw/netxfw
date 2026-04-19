package lifecycle

import (
	"context"
	"fmt"

	"github.com/netxfw/netxfw/internal/api"
	"github.com/netxfw/netxfw/internal/daemon"
	datapathplugins "github.com/netxfw/netxfw/internal/datapath/xdp/plugins"
	datapathprograms "github.com/netxfw/netxfw/internal/datapath/xdp/programs"
	datapathsync "github.com/netxfw/netxfw/internal/datapath/xdp/sync"
	"github.com/netxfw/netxfw/internal/ports"
	"github.com/netxfw/netxfw/internal/utils/logger"
	sdk "github.com/netxfw/netxfw/pkg/sdk"
	"go.uber.org/zap"
)

// Reload performs hot-reload of the XDP program while preserving state when possible.
func Reload(ctx context.Context, pinPath string, cliInterfaces []string, globalCfg *sdk.GlobalConfig) error {
	log := logger.Get(ctx)
	log.Info("[RELOAD] Starting hot-reload of XDP program...")

	if globalCfg == nil {
		return fmt.Errorf("config is nil after loading")
	}

	interfaces, err := ResolveInterfaces(cliInterfaces, globalCfg, log)
	if err != nil {
		return err
	}

	oldManager, err := datapathprograms.OpenPinnedManager(pinPath, log)
	if err != nil {
		log.Info("[INFO]  No existing XDP program found. Performing clean install...")
		_, installErr := Install(ctx, pinPath, cliInterfaces, globalCfg, log)
		return installErr
	}

	return reloadExistingManager(ctx, pinPath, oldManager, globalCfg, interfaces, globalCfg, log)
}

func reloadExistingManager(ctx context.Context, pinPath string, oldManager *datapathprograms.Handle, globalCfg *sdk.GlobalConfig, interfaces []string, oldCfg *sdk.GlobalConfig, log *zap.SugaredLogger) error {
	defer oldManager.Close()

	oldAdapter := datapathprograms.NewAdapter(oldManager)
	pluginCtx := &sdk.RuntimePluginContext{
		Context: ctx,
		Manager: oldAdapter,
		Config:  globalCfg,
		Logger:  log,
	}

	if oldManager.MatchesCapacity(globalCfg.Capacity) {
		return performIncrementalReload(oldManager, globalCfg, interfaces, pluginCtx, oldCfg, log)
	}

	return performFullMigration(ctx, pinPath, oldManager, globalCfg, interfaces, log)
}

func performIncrementalReload(oldManager *datapathprograms.Handle, globalCfg *sdk.GlobalConfig, interfaces []string, pluginCtx *sdk.RuntimePluginContext, oldCfg *sdk.GlobalConfig, log *zap.SugaredLogger) error {
	log.Info("⚡ Capacity unchanged. Performing incremental hot-reload...")

	updater := datapathsync.NewIncrementalUpdater(oldManager)
	if updater != nil {
		diff, diffErr := updater.ComputeDiff(oldCfg, globalCfg)
		if diffErr != nil {
			log.Warnf("[WARN]  Failed to compute config diff: %v", diffErr)
		} else if diff.HasChanges() {
			log.Infof("[STATS] Config changes detected: %s", diff.Summary())
			if err := updater.ApplyDiff(diff); err != nil {
				log.Warnf("[WARN]  Incremental update had errors: %v", err)
			} else {
				log.Info("[OK] Incremental config update applied successfully")
			}
		} else {
			log.Info("[INFO]  No config changes detected")
		}
	}

	daemon.ReloadPlugins(pluginCtx, log)

	if err := oldManager.Attach(interfaces); err != nil {
		log.Warnf("[WARN]  Failed to update XDP program: %v", err)
	}

	log.Info("[START] Incremental reload completed successfully.")
	return nil
}

func performFullMigration(ctx context.Context, pinPath string, oldManager *datapathprograms.Handle, globalCfg *sdk.GlobalConfig, interfaces []string, log *zap.SugaredLogger) error {
	log.Info("[DATA] Capacity changed. Performing full state transfer...")

	newManager, err := datapathprograms.CreateManager(globalCfg.Capacity, log)
	if err != nil {
		return err
	}

	if err := datapathsync.MigrateState(newManager, oldManager); err != nil {
		log.Warnf("[WARN]  State transfer partial or failed: %v", err)
	}
	oldManager.Close()

	if err := newManager.Pin(pinPath); err != nil {
		return fmt.Errorf("failed to pin new maps: %v", err)
	}
	if err := newManager.Attach(interfaces); err != nil {
		return fmt.Errorf("failed to attach new XDP program: %v", err)
	}
	if err := datapathplugins.LoadConfigured(newManager, ports.ConfigFromSDK(globalCfg), log); err != nil {
		log.Warnf("[WARN]  Failed to reload datapath plugins: %v", err)
	}

	newAdapter := datapathprograms.NewAdapter(newManager)
	newSDK := sdk.NewSDK(newAdapter)
	webHost := api.NewServer(newSDK, globalCfg.Web.Port)
	newCtx := daemon.BuildPluginContext(ctx, nil, newAdapter, globalCfg, log, newSDK, webHost)

	daemon.ReloadPlugins(newCtx, log)

	log.Info("[START] Full hot-reload with state transfer completed successfully.")
	return nil
}
