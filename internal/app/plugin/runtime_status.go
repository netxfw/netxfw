package plugin

import (
	runtimehost "github.com/netxfw/netxfw/internal/adapters/plugins/runtime"
	domainruntime "github.com/netxfw/netxfw/internal/domain/plugin/runtime"
	"github.com/netxfw/netxfw/pkg/sdk"
)

// LoadRuntimeStatuses returns runtime plugin status derived from the unified host.
func LoadRuntimeStatuses(cfg *sdk.GlobalConfig) []domainruntime.Status {
	return runtimehost.NewHost(nil).Statuses(cfg)
}
