package plugin

import (
	"context"
	"sort"

	domainconfig "github.com/netxfw/netxfw/internal/domain/config"
	domaindatapath "github.com/netxfw/netxfw/internal/domain/plugin/datapath"
	domainruntime "github.com/netxfw/netxfw/internal/domain/plugin/runtime"
)

// StatusSnapshot captures the unified runtime/datapath plugin read model.
type StatusSnapshot struct {
	Runtime  []domainruntime.Status
	Datapath []domaindatapath.LifecycleStatus
}

// ComposeStatus builds a unified plugin status snapshot.
func ComposeStatus(runtime []domainruntime.Status, datapath []domaindatapath.LifecycleStatus) StatusSnapshot {
	return StatusSnapshot{
		Runtime:  append([]domainruntime.Status(nil), runtime...),
		Datapath: append([]domaindatapath.LifecycleStatus(nil), datapath...),
	}
}

// LoadDatapathStatus returns configured and occupied datapath plugin slots.
func LoadDatapathStatus(ctx context.Context, cfg *domainconfig.Config) ([]domaindatapath.LifecycleStatus, error) {
	slots, listErr := NewDatapathLifecycle().List(ctx)
	slotByIndex := make(map[int]domaindatapath.SlotStatus, len(slots))
	for _, slot := range slots {
		slotByIndex[slot.Index] = slot
	}

	statuses := make([]domaindatapath.LifecycleStatus, 0)
	seen := make(map[int]bool)

	configured := configuredDatapathPlugins(cfg)
	for _, plugin := range configured {
		status := domaindatapath.LifecycleStatus{
			Path:  plugin.Path,
			Index: plugin.Index,
		}
		if slot, ok := slotByIndex[plugin.Index]; ok && slot.Occupied {
			status.Loaded = true
			status.Healthy = true
			status.ProgramID = slot.ProgramID
			status.Message = "loaded"
		} else if listErr != nil {
			status.Message = "configured but pinned runtime unavailable"
		} else {
			status.Message = "configured but not loaded"
		}
		statuses = append(statuses, status)
		seen[plugin.Index] = true
	}

	for _, slot := range slots {
		if !slot.Occupied || seen[slot.Index] {
			continue
		}
		statuses = append(statuses, domaindatapath.LifecycleStatus{
			Index:     slot.Index,
			Loaded:    true,
			ProgramID: slot.ProgramID,
			Message:   "loaded but not configured",
		})
	}

	sort.Slice(statuses, func(i, j int) bool {
		return statuses[i].Index < statuses[j].Index
	})

	return statuses, listErr
}

func configuredDatapathPlugins(cfg *domainconfig.Config) []domainconfig.BPFPluginConfig {
	if cfg == nil || !cfg.BPFPlugin.Enabled {
		return nil
	}

	items := make([]domainconfig.BPFPluginConfig, 0, len(cfg.BPFPlugin.Plugins))
	for _, plugin := range cfg.BPFPlugin.Plugins {
		if !plugin.Enabled {
			continue
		}
		items = append(items, plugin)
	}
	return items
}
