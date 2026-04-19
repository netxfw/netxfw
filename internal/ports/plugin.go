package ports

import (
	domainconfig "github.com/netxfw/netxfw/internal/domain/config"
	domaindatapath "github.com/netxfw/netxfw/internal/domain/plugin/datapath"
	domainruntime "github.com/netxfw/netxfw/internal/domain/plugin/runtime"
)

// PluginType identifies runtime plugin criticality without pushing sdk inward.
type PluginType string

const (
	PluginTypeCore      PluginType = "core"
	PluginTypeExtension PluginType = "extension"
)

// RuntimePlugin exposes the minimal app-facing runtime plugin descriptor surface.
type RuntimePlugin interface {
	Name() string
	Type() PluginType
}

// RuntimeRegistry exposes runtime plugin discovery to the app layer.
type RuntimeRegistry interface {
	Plugins() []RuntimePlugin
	Inventory() []domainruntime.Descriptor
}

// RuntimeStatusReader exposes runtime plugin status projection.
type RuntimeStatusReader interface {
	Statuses(cfg *domainconfig.Config) []domainruntime.Status
}

// DatapathLifecycle exposes datapath plugin lifecycle operations.
type DatapathLifecycle interface {
	Execute(cmd domaindatapath.Command) error
	List() ([]domaindatapath.SlotStatus, error)
	SlotRange() domaindatapath.SlotRange
}
