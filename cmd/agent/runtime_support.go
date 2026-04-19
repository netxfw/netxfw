package agent

import (
	"context"
	"time"

	"github.com/netxfw/netxfw/internal/app"
	appconfig "github.com/netxfw/netxfw/internal/app/config"
	applugin "github.com/netxfw/netxfw/internal/app/plugin"
	"github.com/netxfw/netxfw/pkg/sdk"
)

type commandRuntimeSupport struct{}
type systemServiceSupport struct{}
type systemQuerySupport struct{}
type performanceQuerySupport struct{}
type performanceProvider interface {
	PerfStats() any
}

type TrafficStats = app.TrafficStats
type MetricsData = app.MetricsData
type InterfaceXDPInfo = app.InterfaceXDPInfo
type StatusSnapshot = appconfig.StatusSnapshot
type PluginStatusSnapshot = applugin.StatusSnapshot
type PluginHealthSnapshot = applugin.HealthSnapshot
type PerformanceStats = app.PerformanceStats
type OperationStats = app.OperationStats

var commandRuntimeService = commandRuntimeSupport{}
var systemService = systemServiceSupport{}
var systemQueryService = systemQuerySupport{}
var perfQueryService = performanceQuerySupport{}

func (commandRuntimeSupport) SetConfigPath(path string) {
	appconfig.SetConfigPath(path)
}

func (commandRuntimeSupport) LoadConfig() (*sdk.GlobalConfig, error) {
	return appconfig.LoadConfig()
}

func (commandRuntimeSupport) IsTestMode() bool {
	return app.IsTestMode()
}

func (commandRuntimeSupport) IsXDPLoaded() bool {
	return app.IsXDPLoaded()
}

func (commandRuntimeSupport) GetRuntimeMode() string {
	return app.GetRuntimeMode()
}

func (commandRuntimeSupport) LoadTrafficStats() (TrafficStats, error) {
	return app.LoadTrafficStats()
}

func (commandRuntimeSupport) FormatNumberWithComma(n uint64) string {
	return app.FormatNumberWithComma(n)
}

func (commandRuntimeSupport) FormatBPS(bps uint64) string {
	return app.FormatBPS(bps)
}

func (commandRuntimeSupport) LoadAndSyncConfigToRuntime(fw *sdk.SDK) error {
	return app.LoadAndSyncConfigToRuntime(fw)
}

func (commandRuntimeSupport) RunDeployUpdate() error {
	return app.RunDeployUpdate()
}

func (commandRuntimeSupport) Version() string {
	return app.Version()
}

func (commandRuntimeSupport) LoadPlugin(ctx context.Context, path string, index int) error {
	return applugin.Load(ctx, path, index)
}

func (commandRuntimeSupport) RemovePlugin(ctx context.Context, index int) error {
	return applugin.Remove(ctx, index)
}

func (commandRuntimeSupport) ListLoadedPlugins(ctx context.Context) ([]applugin.LoadedSlot, error) {
	return applugin.ListLoaded(ctx)
}

func (commandRuntimeSupport) ClearBlacklist(ctx context.Context, dynamic bool) error {
	return app.ClearBlacklist(ctx, dynamic)
}

func (commandRuntimeSupport) ResetFirewall(fw *sdk.SDK) app.ResetResult {
	return app.ResetFirewall(fw)
}

func (systemServiceSupport) InstallXDP(ctx context.Context, interfaces []string) error {
	return app.InstallXDP(ctx, interfaces)
}

func (systemServiceSupport) RemoveXDP(ctx context.Context, interfaces []string) error {
	return app.RemoveXDP(ctx, interfaces)
}

func (systemServiceSupport) ReloadXDP(ctx context.Context, interfaces []string) error {
	return app.ReloadXDP(ctx, interfaces)
}

func (systemServiceSupport) AttachXDPWithMode(ctx context.Context, interfaces []string, mode string) ([]string, error) {
	return app.ValidateAndAttachXDP(ctx, interfaces, mode)
}

func (systemServiceSupport) ReloadPinnedMaps(ctx context.Context) error {
	return app.ReloadPinnedMaps(ctx)
}

func (systemServiceSupport) SyncRuntimeToConfig(fw *sdk.SDK) error {
	return app.SyncRuntimeToConfig(fw)
}

func (systemServiceSupport) SyncConfigToRuntimeOverwrite(fw *sdk.SDK) error {
	return app.SyncConfigToRuntimeOverwrite(fw)
}

func (systemServiceSupport) InitConfiguration(ctx context.Context) {
	app.InitConfiguration(ctx)
}

func (systemServiceSupport) TestConfiguration(ctx context.Context) {
	app.TestConfiguration(ctx)
}

func (systemServiceSupport) RunDaemon(ctx context.Context) {
	app.RunDaemon(ctx)
}

func (systemServiceSupport) RunShellPipeline(command string) error {
	return app.RunShellPipeline(command)
}

func (systemQuerySupport) LoadConfig() (*sdk.GlobalConfig, error) {
	return appconfig.LoadConfig()
}

func (systemQuerySupport) LoadStatusSnapshot(source any) (StatusSnapshot, error) {
	return appconfig.LoadStatusSnapshot(source)
}

func (systemQuerySupport) LoadTrafficStats() (TrafficStats, error) {
	return app.LoadTrafficStats()
}

func (systemQuerySupport) LoadMetrics(source any) (*MetricsData, error) {
	return app.LoadMetrics(source)
}

func (systemQuerySupport) LoadPluginStatus(ctx context.Context, cfg *sdk.GlobalConfig) (PluginStatusSnapshot, error) {
	runtimeStatuses := applugin.LoadRuntimeStatuses(cfg)
	datapath, err := applugin.LoadDatapathStatus(ctx, cfg)
	return applugin.ComposeStatus(runtimeStatuses, datapath), err
}

func (systemQuerySupport) LoadPluginHealth(snapshot PluginStatusSnapshot) PluginHealthSnapshot {
	return applugin.SummarizeHealth(snapshot)
}

func (systemQuerySupport) GetAttachedInterfaceInfos() ([]InterfaceXDPInfo, error) {
	return app.GetAttachedInterfaceInfos()
}

func (systemQuerySupport) GetConntrackMax() int {
	return appconfig.GetConntrackMax()
}

func (systemQuerySupport) FormatNumberWithComma(n uint64) string {
	return app.FormatNumberWithComma(n)
}

func (systemQuerySupport) FormatBPS(bps uint64) string {
	return app.FormatBPS(bps)
}

func (systemQuerySupport) FormatDuration(d time.Duration) string {
	return app.FormatDuration(d)
}

func (performanceQuerySupport) LoadPerformanceStats(source performanceProvider) (*PerformanceStats, error) {
	return app.LoadPerformanceStats(source)
}

func (performanceQuerySupport) FormatLatency(ns uint64) string {
	return app.FormatLatency(ns)
}

func (performanceQuerySupport) FormatNumber(n uint64) string {
	return app.FormatNumber(n)
}

func (performanceQuerySupport) FormatBytes(b uint64) string {
	return app.FormatBytes(b)
}
