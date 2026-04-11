package services

import (
	"context"

	"github.com/netxfw/netxfw/internal/app"
	"github.com/netxfw/netxfw/pkg/sdk"
)

// CommandRuntimeService centralizes runtime/config helpers needed by command layer.
type CommandRuntimeService struct{}

func NewCommandRuntimeService() *CommandRuntimeService {
	return &CommandRuntimeService{}
}

func (s *CommandRuntimeService) SetConfigPath(path string) {
	app.SetConfigPath(path)
}

func (s *CommandRuntimeService) LoadConfig() (*sdk.GlobalConfig, error) {
	return app.LoadConfig()
}

func (s *CommandRuntimeService) IsTestMode() bool {
	return app.IsTestMode()
}

func (s *CommandRuntimeService) IsXDPLoaded() bool {
	return app.IsXDPLoaded()
}

func (s *CommandRuntimeService) GetRuntimeMode() string {
	return app.GetRuntimeMode()
}

func (s *CommandRuntimeService) LoadTrafficStats() (app.TrafficStats, error) {
	return app.LoadTrafficStats()
}

func (s *CommandRuntimeService) FormatNumberWithComma(n uint64) string {
	return app.FormatNumberWithComma(n)
}

func (s *CommandRuntimeService) FormatBPS(bps uint64) string {
	return app.FormatBPS(bps)
}

func (s *CommandRuntimeService) LoadAndSyncConfigToRuntime(fw *sdk.SDK) error {
	return app.LoadAndSyncConfigToRuntime(fw)
}

func (s *CommandRuntimeService) RunDeployUpdate() error {
	return app.RunDeployUpdate()
}

func (s *CommandRuntimeService) Version() string {
	return app.Version()
}

func (s *CommandRuntimeService) LoadPlugin(ctx context.Context, path string, index int) error {
	return app.LoadPlugin(ctx, path, index)
}

func (s *CommandRuntimeService) RemovePlugin(ctx context.Context, index int) error {
	return app.RemovePlugin(ctx, index)
}

func (s *CommandRuntimeService) ListLoadedPlugins(ctx context.Context) ([]app.PluginSlot, error) {
	return app.ListLoadedPlugins(ctx)
}

func (s *CommandRuntimeService) ClearBlacklist(ctx context.Context, dynamic bool) error {
	return app.ClearBlacklist(ctx, dynamic)
}

func (s *CommandRuntimeService) ResetFirewall(fw *sdk.SDK) app.ResetResult {
	return app.ResetFirewall(fw)
}
