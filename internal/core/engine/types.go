package engine

import (
	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/pkg/sdk"
)

// CoreModule defines the interface for core firewall modules (IP, Port, RateLimit, etc.).
type CoreModule interface {
	// Name returns the module name.
	Name() string
	// Init initializes the module with configuration and dependencies.
	Init(cfg *types.GlobalConfig, s *sdk.SDK, logger sdk.Logger) error
	// Start starts the module logic (e.g. syncing rules).
	Start() error
	// Reload updates the module with new configuration.
	Reload(cfg *types.GlobalConfig) error
	// Stop stops the module.
	Stop() error
}
