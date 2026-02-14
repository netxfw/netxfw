package daemon

import (
	"github.com/livp123/netxfw/internal/xdp"
)

// DaemonOptions configuration options for the daemon
type DaemonOptions struct {
	// Manager allows injecting a custom/mock XDP manager.
	// If nil, the default manager will be created.
	Manager xdp.ManagerInterface
}
