package plugin

import (
	"context"

	domaindatapath "github.com/netxfw/netxfw/internal/domain/plugin/datapath"
)

// LoadedSlot captures an occupied datapath plugin slot.
type LoadedSlot struct {
	Index   int
	Program uint32
}

// Load inserts a datapath plugin into the pinned runtime.
func Load(ctx context.Context, path string, index int) error {
	return NewDatapathLifecycle().Execute(ctx, domaindatapath.Command{
		Action: "load",
		Path:   path,
		Index:  index,
	})
}

// Remove detaches a datapath plugin from the pinned runtime.
func Remove(ctx context.Context, index int) error {
	return NewDatapathLifecycle().Execute(ctx, domaindatapath.Command{
		Action: "remove",
		Index:  index,
	})
}

// ListLoaded returns the occupied datapath plugin slots.
func ListLoaded(ctx context.Context) ([]LoadedSlot, error) {
	items, err := NewDatapathLifecycle().List(ctx)
	if err != nil {
		return nil, err
	}

	slots := make([]LoadedSlot, 0, len(items))
	for _, item := range items {
		if !item.Occupied {
			continue
		}
		slots = append(slots, LoadedSlot{
			Index:   item.Index,
			Program: item.ProgramID,
		})
	}
	return slots, nil
}
