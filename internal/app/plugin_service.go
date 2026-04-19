package app

import (
	"context"
	"fmt"
	"strconv"

	applugin "github.com/netxfw/netxfw/internal/app/plugin"
	domaindatapath "github.com/netxfw/netxfw/internal/domain/plugin/datapath"
	domainruntime "github.com/netxfw/netxfw/internal/domain/plugin/runtime"
	"github.com/netxfw/netxfw/internal/ports"
	sdk "github.com/netxfw/netxfw/pkg/sdk"
)

// PluginCommandRequest describes a plugin operation request.
type PluginCommandRequest struct {
	Action string
	Path   string
	Index  int
}

type PluginStatusSnapshot = applugin.StatusSnapshot
type PluginHealthSnapshot = applugin.HealthSnapshot

// NewRuntimePluginStatuses returns runtime plugin status derived from the unified host.
func NewRuntimePluginStatuses(cfg *sdk.GlobalConfig) []domainruntime.Status {
	return applugin.LoadRuntimeStatuses(ports.ConfigFromSDK(cfg))
}

// LoadPlugin loads a plugin into the pinned runtime.
func LoadPlugin(ctx context.Context, path string, index int) error {
	return applugin.Load(ctx, path, index)
}

// RemovePlugin removes a plugin from the pinned runtime.
func RemovePlugin(ctx context.Context, index int) error {
	return applugin.Remove(ctx, index)
}

// ExecutePluginCommand processes plugin-related app operations.
func ExecutePluginCommand(ctx context.Context, req PluginCommandRequest) error {
	return applugin.NewDatapathLifecycle().Execute(ctx, domaindatapath.Command{
		Action: req.Action,
		Path:   req.Path,
		Index:  req.Index,
	})
}

// HandlePluginCommand keeps older arg-based callers working.
func HandlePluginCommand(ctx context.Context, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: netxfw plugin <load|remove|list>")
	}

	req := PluginCommandRequest{Action: args[0]}
	switch req.Action {
	case "load":
		if len(args) < 3 {
			return fmt.Errorf("Usage: netxfw plugin load <path_to_elf> <index (2-15)>")
		}
		idx, err := strconv.Atoi(args[2])
		if err != nil {
			return fmt.Errorf("invalid index: %v", err)
		}
		req.Path = args[1]
		req.Index = idx
	case "remove":
		if len(args) < 2 {
			return fmt.Errorf("Usage: netxfw plugin remove <index (2-15)>")
		}
		idx, err := strconv.Atoi(args[1])
		if err != nil {
			return fmt.Errorf("invalid index: %v", err)
		}
		req.Index = idx
	case "list":
		return nil
	default:
		return fmt.Errorf("unknown plugin command: %s", req.Action)
	}

	return ExecutePluginCommand(ctx, req)
}

// ListLoadedPlugins lists currently occupied plugin slots.
func ListLoadedPlugins(ctx context.Context) ([]PluginSlot, error) {
	items, err := applugin.ListLoaded(ctx)
	if err != nil {
		return nil, err
	}

	slots := make([]PluginSlot, 0, len(items))
	for _, item := range items {
		slots = append(slots, PluginSlot{Index: item.Index, Program: item.Program})
	}
	return slots, nil
}

// LoadPluginStatus loads unified runtime/datapath plugin status.
func LoadPluginStatus(ctx context.Context, runtime []domainruntime.Status, cfg *sdk.GlobalConfig) (PluginStatusSnapshot, error) {
	datapath, err := applugin.LoadDatapathStatus(ctx, ports.ConfigFromSDK(cfg))
	return applugin.ComposeStatus(runtime, datapath), err
}

// LoadPluginHealth summarizes unified plugin health from status.
func LoadPluginHealth(snapshot PluginStatusSnapshot) PluginHealthSnapshot {
	return applugin.SummarizeHealth(snapshot)
}
