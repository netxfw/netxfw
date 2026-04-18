package app

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/netxfw/netxfw/internal/api"
	"github.com/netxfw/netxfw/internal/utils/logger"
	"github.com/netxfw/netxfw/internal/datapath/xdp/backend"
	"github.com/netxfw/netxfw/pkg/sdk"
)

// RunWebServer starts the API and UI server.
func RunWebServer(ctx context.Context, port int) error {
	log := logger.Get(ctx)
	manager, err := xdp.NewManagerFromPins(GetPinPath(), log)
	if err != nil {
		log.Warnf("[WARN]  Could not load pinned maps (is XDP loaded?): %v", err)
		return fmt.Errorf("web server requires netxfw XDP to be loaded. Run 'netxfw system load' first")
	}
	defer manager.Close()

	adapter := xdp.NewAdapter(manager)
	s := sdk.NewSDK(adapter)
	server := api.NewServer(s, port)
	if err := server.EnsureHandlerInitialized(); err != nil {
		return fmt.Errorf("failed to initialize web server: %w", err)
	}

	addr := fmt.Sprintf(":%d", port)
	log.Infof("[START] Management API and UI starting on http://localhost%s", addr)

	httpServer := &http.Server{
		Addr:         addr,
		Handler:      server.Handler(),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	if err := httpServer.ListenAndServe(); err != nil {
		return fmt.Errorf("failed to start web server: %v", err)
	}
	return nil
}
