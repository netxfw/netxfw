package app

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/netxfw/netxfw/internal/api"
	appconfig "github.com/netxfw/netxfw/internal/app/config"
	datapathprograms "github.com/netxfw/netxfw/internal/datapath/xdp/programs"
	"github.com/netxfw/netxfw/internal/utils/logger"
	sdk "github.com/netxfw/netxfw/pkg/sdk"
)

const defaultHTTPBind = "127.0.0.1"

// RunWebServer starts the API and UI server.
func RunWebServer(ctx context.Context, port int) error {
	log := logger.Get(ctx)
	manager, err := datapathprograms.OpenPinnedManager(GetPinPath(), log)
	if err != nil {
		log.Warnf("[WARN]  Could not load pinned maps (is XDP loaded?): %v", err)
		return fmt.Errorf("web server requires netxfw XDP to be loaded. Run 'netxfw system load' first")
	}
	defer manager.Close()

	adapter := datapathprograms.NewAdapter(manager)
	s := sdk.NewSDK(adapter)
	server := api.NewServer(s, port)
	if initErr := server.EnsureHandlerInitialized(); initErr != nil {
		return fmt.Errorf("failed to initialize web server: %w", initErr)
	}
	cfg, err := appconfig.LoadConfig()
	if err != nil {
		return fmt.Errorf("failed to load web config: %w", err)
	}
	bind := defaultHTTPBind
	if cfg != nil && cfg.Web.Bind != "" {
		bind = cfg.Web.Bind
	}

	addr := net.JoinHostPort(bind, strconv.Itoa(port))
	log.Infof("[START] Management API and UI starting on http://%s", addr)

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
