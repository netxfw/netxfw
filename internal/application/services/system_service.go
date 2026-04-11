package services

import (
	"context"

	"github.com/netxfw/netxfw/internal/app"
	"github.com/netxfw/netxfw/pkg/sdk"
)

// SystemService centralizes system-level runtime operations for CLI.
type SystemService struct{}

func NewSystemService() *SystemService {
	return &SystemService{}
}

func (s *SystemService) InstallXDP(ctx context.Context, interfaces []string) error {
	return app.InstallXDP(ctx, interfaces)
}

func (s *SystemService) RemoveXDP(ctx context.Context, interfaces []string) error {
	return app.RemoveXDP(ctx, interfaces)
}

func (s *SystemService) ReloadXDP(ctx context.Context, interfaces []string) error {
	return app.ReloadXDP(ctx, interfaces)
}

func (s *SystemService) AttachXDPWithMode(ctx context.Context, interfaces []string, mode string) ([]string, error) {
	return app.ValidateAndAttachXDP(ctx, interfaces, mode)
}

func (s *SystemService) ReloadPinnedMaps(ctx context.Context) error {
	return app.ReloadPinnedMaps(ctx)
}

func (s *SystemService) SyncRuntimeToConfig(fw *sdk.SDK) error {
	return app.SyncRuntimeToConfig(fw)
}

func (s *SystemService) SyncConfigToRuntimeOverwrite(fw *sdk.SDK) error {
	return app.SyncConfigToRuntimeOverwrite(fw)
}

func (s *SystemService) InitConfiguration(ctx context.Context) {
	app.InitConfiguration(ctx)
}

func (s *SystemService) TestConfiguration(ctx context.Context) {
	app.TestConfiguration(ctx)
}

func (s *SystemService) RunDaemon(ctx context.Context) {
	app.RunDaemon(ctx)
}

func (s *SystemService) RunShellPipeline(command string) error {
	return app.RunShellPipeline(command)
}
