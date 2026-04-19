package plugin

import (
	"context"

	datapathplugins "github.com/netxfw/netxfw/internal/datapath/xdp/plugins"
	domaindatapath "github.com/netxfw/netxfw/internal/domain/plugin/datapath"
	"github.com/netxfw/netxfw/internal/runtime"
)

// DatapathLifecycle exposes datapath plugin lifecycle operations.
type DatapathLifecycle interface {
	Execute(ctx context.Context, cmd domaindatapath.Command) error
	List(ctx context.Context) ([]domaindatapath.SlotStatus, error)
	SlotRange() domaindatapath.SlotRange
}

type pinnedDatapathLifecycle struct{}

// NewDatapathLifecycle returns the datapath plugin lifecycle facade.
func NewDatapathLifecycle() DatapathLifecycle {
	return pinnedDatapathLifecycle{}
}

func (pinnedDatapathLifecycle) Execute(ctx context.Context, cmd domaindatapath.Command) error {
	return datapathplugins.ExecutePinned(ctx, runtime.GetPinPath(), cmd)
}

func (pinnedDatapathLifecycle) List(ctx context.Context) ([]domaindatapath.SlotStatus, error) {
	return datapathplugins.ListPinned(ctx, runtime.GetPinPath())
}

func (pinnedDatapathLifecycle) SlotRange() domaindatapath.SlotRange {
	return datapathplugins.SlotRange()
}
