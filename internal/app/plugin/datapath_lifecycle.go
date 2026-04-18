package plugin

import (
	"context"

	"github.com/netxfw/netxfw/internal/config"
	datapathplugins "github.com/netxfw/netxfw/internal/datapath/xdp/plugins"
	domaindatapath "github.com/netxfw/netxfw/internal/domain/plugin/datapath"
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
	return datapathplugins.ExecutePinned(ctx, config.GetPinPath(), cmd)
}

func (pinnedDatapathLifecycle) List(ctx context.Context) ([]domaindatapath.SlotStatus, error) {
	return datapathplugins.ListPinned(ctx, config.GetPinPath())
}

func (pinnedDatapathLifecycle) SlotRange() domaindatapath.SlotRange {
	return datapathplugins.SlotRange()
}
