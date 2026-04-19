package syncbridge

import (
	xdpbackend "github.com/netxfw/netxfw/internal/adapters/datapath/xdpbackend"
	backendxdp "github.com/netxfw/netxfw/internal/datapath/xdp/backend"
	"github.com/netxfw/netxfw/pkg/sdk"
)

type Manager = xdpbackend.Handle

type ConfigChange struct {
	Field    string
	OldValue any
	NewValue any
}

type IPPortRuleChange struct {
	IP     string
	Port   uint16
	Action uint8
}

type RateLimitChange struct {
	CIDR  string
	Rate  uint64
	Burst uint64
}

type ConfigDiff struct {
	GlobalConfigChanges map[string]ConfigChange
	BlacklistAdded      []string
	BlacklistRemoved    []string
	WhitelistAdded      []string
	WhitelistRemoved    []string
	IPPortAdded         []IPPortRuleChange
	IPPortRemoved       []IPPortRuleChange
	RateLimitAdded      []RateLimitChange
	RateLimitRemoved    []RateLimitChange
	RateLimitUpdated    []RateLimitChange
}

type Updater struct {
	inner *backendxdp.IncrementalUpdater
}

func NewIncrementalUpdater(manager *Manager) *Updater {
	if manager == nil {
		return nil
	}
	return &Updater{inner: backendxdp.NewIncrementalUpdater(manager.BackendManager())}
}

func (u *Updater) ComputeDiff(oldCfg, newCfg *sdk.GlobalConfig) (*ConfigDiff, error) {
	if u == nil || u.inner == nil {
		return nil, nil
	}
	diff, err := u.inner.ComputeDiff(oldCfg, newCfg)
	if err != nil {
		return nil, err
	}
	return convertConfigDiff(diff), nil
}

func (u *Updater) ApplyDiff(diff *ConfigDiff) error {
	if u == nil || u.inner == nil {
		return nil
	}
	return u.inner.ApplyDiff(toBackendConfigDiff(diff))
}

func (d *ConfigDiff) HasChanges() bool {
	return len(d.GlobalConfigChanges) > 0 ||
		len(d.BlacklistAdded) > 0 ||
		len(d.BlacklistRemoved) > 0 ||
		len(d.WhitelistAdded) > 0 ||
		len(d.WhitelistRemoved) > 0 ||
		len(d.IPPortAdded) > 0 ||
		len(d.IPPortRemoved) > 0 ||
		len(d.RateLimitAdded) > 0 ||
		len(d.RateLimitRemoved) > 0 ||
		len(d.RateLimitUpdated) > 0
}

func (d *ConfigDiff) Summary() string {
	return toBackendConfigDiff(d).Summary()
}

func convertConfigDiff(diff *backendxdp.ConfigDiff) *ConfigDiff {
	if diff == nil {
		return nil
	}

	global := make(map[string]ConfigChange, len(diff.GlobalConfigChanges))
	for field, change := range diff.GlobalConfigChanges {
		global[field] = ConfigChange{
			Field:    change.Field,
			OldValue: change.OldValue,
			NewValue: change.NewValue,
		}
	}

	return &ConfigDiff{
		GlobalConfigChanges: global,
		BlacklistAdded:      append([]string(nil), diff.BlacklistAdded...),
		BlacklistRemoved:    append([]string(nil), diff.BlacklistRemoved...),
		WhitelistAdded:      append([]string(nil), diff.WhitelistAdded...),
		WhitelistRemoved:    append([]string(nil), diff.WhitelistRemoved...),
		IPPortAdded:         convertIPPortRuleChanges(diff.IPPortAdded),
		IPPortRemoved:       convertIPPortRuleChanges(diff.IPPortRemoved),
		RateLimitAdded:      convertRateLimitChanges(diff.RateLimitAdded),
		RateLimitRemoved:    convertRateLimitChanges(diff.RateLimitRemoved),
		RateLimitUpdated:    convertRateLimitChanges(diff.RateLimitUpdated),
	}
}

func toBackendConfigDiff(diff *ConfigDiff) *backendxdp.ConfigDiff {
	if diff == nil {
		return nil
	}

	global := make(map[string]backendxdp.ConfigChange, len(diff.GlobalConfigChanges))
	for field, change := range diff.GlobalConfigChanges {
		global[field] = backendxdp.ConfigChange{
			Field:    change.Field,
			OldValue: change.OldValue,
			NewValue: change.NewValue,
		}
	}

	return &backendxdp.ConfigDiff{
		GlobalConfigChanges: global,
		BlacklistAdded:      append([]string(nil), diff.BlacklistAdded...),
		BlacklistRemoved:    append([]string(nil), diff.BlacklistRemoved...),
		WhitelistAdded:      append([]string(nil), diff.WhitelistAdded...),
		WhitelistRemoved:    append([]string(nil), diff.WhitelistRemoved...),
		IPPortAdded:         toBackendIPPortRuleChanges(diff.IPPortAdded),
		IPPortRemoved:       toBackendIPPortRuleChanges(diff.IPPortRemoved),
		RateLimitAdded:      toBackendRateLimitChanges(diff.RateLimitAdded),
		RateLimitRemoved:    toBackendRateLimitChanges(diff.RateLimitRemoved),
		RateLimitUpdated:    toBackendRateLimitChanges(diff.RateLimitUpdated),
	}
}

func convertIPPortRuleChanges(changes []backendxdp.IPPortRuleChange) []IPPortRuleChange {
	if len(changes) == 0 {
		return nil
	}
	converted := make([]IPPortRuleChange, 0, len(changes))
	for _, change := range changes {
		converted = append(converted, IPPortRuleChange{
			IP:     change.IP,
			Port:   change.Port,
			Action: change.Action,
		})
	}
	return converted
}

func toBackendIPPortRuleChanges(changes []IPPortRuleChange) []backendxdp.IPPortRuleChange {
	if len(changes) == 0 {
		return nil
	}
	converted := make([]backendxdp.IPPortRuleChange, 0, len(changes))
	for _, change := range changes {
		converted = append(converted, backendxdp.IPPortRuleChange{
			IP:     change.IP,
			Port:   change.Port,
			Action: change.Action,
		})
	}
	return converted
}

func convertRateLimitChanges(changes []backendxdp.RateLimitChange) []RateLimitChange {
	if len(changes) == 0 {
		return nil
	}
	converted := make([]RateLimitChange, 0, len(changes))
	for _, change := range changes {
		converted = append(converted, RateLimitChange{
			CIDR:  change.CIDR,
			Rate:  change.Rate,
			Burst: change.Burst,
		})
	}
	return converted
}

func toBackendRateLimitChanges(changes []RateLimitChange) []backendxdp.RateLimitChange {
	if len(changes) == 0 {
		return nil
	}
	converted := make([]backendxdp.RateLimitChange, 0, len(changes))
	for _, change := range changes {
		converted = append(converted, backendxdp.RateLimitChange{
			CIDR:  change.CIDR,
			Rate:  change.Rate,
			Burst: change.Burst,
		})
	}
	return converted
}
