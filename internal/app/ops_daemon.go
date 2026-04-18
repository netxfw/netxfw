package app

import (
	"context"
	"fmt"

	"github.com/netxfw/netxfw/internal/config"
	"github.com/netxfw/netxfw/internal/utils/logger"
	"github.com/netxfw/netxfw/internal/version"
	"github.com/netxfw/netxfw/internal/datapath/xdp/backend"
	"github.com/netxfw/netxfw/pkg/sdk"
)

// InitRootCommandContext initializes logging for CLI root commands and injects logger into context.
func InitRootCommandContext(ctx context.Context) context.Context {
	cfg, err := config.ReloadCurrentConfig()
	if err != nil {
		logger.Init(logger.LoggingConfig{Enabled: true, Level: "info"})
	} else {
		logger.Init(cfg.Logging)
	}

	return logger.WithContext(ctx, logger.Get(nil))
}

// BootstrapDaemon initializes a default logger, sets runtime mode, and returns a context with logger.
func BootstrapDaemon(mode string) context.Context {
	logger.Init(logger.LoggingConfig{Enabled: true, Level: "info"})
	SetRuntimeMode(mode)

	ctx := context.Background()
	ctx = logger.WithContext(ctx, logger.Get(nil))
	logger.Get(ctx).Infof("Starting netxfw-%s %s...", mode, version.Version)
	return ctx
}

// NewPinnedSDK returns an SDK connected to the currently pinned maps.
func NewPinnedSDK() (*sdk.SDK, error) {
	mgr, err := xdp.NewManagerFromPins(GetPinPath(), logger.Get(nil))
	if err != nil {
		return nil, fmt.Errorf("failed to load XDP manager from %s: %w", GetPinPath(), err)
	}
	return sdk.NewSDK(xdp.NewAdapter(mgr)), nil
}

// SyncLogger flushes any buffered logs.
func SyncLogger() {
	_ = logger.Sync()
}
