package plugin

import (
	runtimehost "github.com/netxfw/netxfw/internal/adapters/plugins/runtime"
	domainconfig "github.com/netxfw/netxfw/internal/domain/config"
	domainruntime "github.com/netxfw/netxfw/internal/domain/plugin/runtime"
)

// LoadRuntimeStatuses returns runtime plugin status derived from the unified host.
func LoadRuntimeStatuses(cfg *domainconfig.Config) []domainruntime.Status {
	return runtimehost.NewHost(nil).Statuses(cfg)
}
