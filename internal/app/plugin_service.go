package app

import (
	"context"
	"fmt"
	"strconv"

	"github.com/netxfw/netxfw/internal/utils/logger"
	"github.com/netxfw/netxfw/internal/xdp"
)

// PluginCommandRequest describes a plugin operation request.
type PluginCommandRequest struct {
	Action string
	Path   string
	Index  int
}

// LoadPlugin loads a plugin into the pinned runtime.
func LoadPlugin(ctx context.Context, path string, index int) error {
	return ExecutePluginCommand(ctx, PluginCommandRequest{Action: "load", Path: path, Index: index})
}

// RemovePlugin removes a plugin from the pinned runtime.
func RemovePlugin(ctx context.Context, index int) error {
	return ExecutePluginCommand(ctx, PluginCommandRequest{Action: "remove", Index: index})
}

// ExecutePluginCommand processes plugin-related app operations.
func ExecutePluginCommand(ctx context.Context, req PluginCommandRequest) error {
	log := logger.Get(ctx)

	manager, err := xdp.NewManagerFromPins(GetPinPath(), log)
	if err != nil {
		return fmt.Errorf("failed to load XDP manager: %v (Is the firewall running?)", err)
	}
	defer manager.Close()

	switch req.Action {
	case "load":
		if req.Path == "" {
			return fmt.Errorf("plugin path is required")
		}
		if err := manager.LoadPlugin(req.Path, req.Index); err != nil {
			return fmt.Errorf("failed to load plugin: %v", err)
		}
	case "remove":
		if err := manager.RemovePlugin(req.Index); err != nil {
			return fmt.Errorf("failed to remove plugin: %v", err)
		}
	default:
		return fmt.Errorf("unknown plugin command: %s", req.Action)
	}

	log.Infof("[OK] Plugin command %s executed successfully", req.Action)
	return nil
}

// HandlePluginCommand maintains compatibility with legacy arg-based callers.
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
	log := logger.Get(ctx)
	manager, err := xdp.NewManagerFromPins(GetPinPath(), log)
	if err != nil {
		return nil, fmt.Errorf("failed to load XDP manager: %v (Is the firewall running?)", err)
	}
	defer manager.Close()

	var slots []PluginSlot
	for i := xdp.ProgIdxPluginStart; i <= xdp.ProgIdxPluginEnd; i++ {
		var progID uint32
		if err := manager.JmpTable().Lookup(uint32(i), &progID); err == nil {
			slots = append(slots, PluginSlot{Index: i, Program: progID})
		}
	}
	return slots, nil
}
