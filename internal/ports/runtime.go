package ports

import (
	domainruntime "github.com/netxfw/netxfw/internal/domain/plugin/runtime"
)

// RuntimeHost exposes the lifecycle of long-running runtime plugins.
type RuntimeHost interface {
	Inventory() []domainruntime.Descriptor
}
