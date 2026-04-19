package rule

import (
	"github.com/netxfw/netxfw/internal/domain/config"
	"github.com/netxfw/netxfw/internal/ports"
	sdk "github.com/netxfw/netxfw/pkg/sdk"
)

// Snapshot captures the minimal read model shared by rule-oriented commands.
type Snapshot struct {
	Blacklist []ports.BlockedIP
	Whitelist []string
	IPPort    []config.IPPortRule
}

func List(fw *sdk.SDK, limit int, search string) (Snapshot, error) {
	return ListWithRuntime(NewRuntime(fw), limit, search)
}

func ListWithRuntime(runtime ruleRuntime, limit int, search string) (Snapshot, error) {
	snapshot := Snapshot{}

	blacklist, _, err := runtime.Blacklist().List(limit, search)
	if err != nil {
		return Snapshot{}, err
	}
	whitelist, _, err := runtime.Whitelist().List(limit, search)
	if err != nil {
		return Snapshot{}, err
	}
	ipPort, _, err := runtime.Rule().ListIPPortRules(limit, search)
	if err != nil {
		return Snapshot{}, err
	}

	snapshot.Blacklist = blacklist
	snapshot.Whitelist = whitelist
	snapshot.IPPort = ipPort
	return snapshot, nil
}
