package maps

import (
	"fmt"

	backendxdp "github.com/netxfw/netxfw/internal/datapath/xdp/backend"
	datapathprograms "github.com/netxfw/netxfw/internal/datapath/xdp/programs"
	"go.uber.org/zap"
)

// ExpiredCleanupSummary reports how many expired entries were removed per map.
type ExpiredCleanupSummary struct {
	Locked    int
	Whitelist int
	IPPort    int
}

// Total returns the total number of removed entries across tracked maps.
func (s ExpiredCleanupSummary) Total() int {
	return s.Locked + s.Whitelist + s.IPPort
}

// ClearPinnedBlacklist clears the configured blacklist map from the pinned manager.
func ClearPinnedBlacklist(pinPath string, dynamic bool, log *zap.SugaredLogger) error {
	manager, err := datapathprograms.OpenPinnedManager(pinPath, log)
	if err != nil {
		return fmt.Errorf("failed to load XDP manager: %v (Is the firewall running?)", err)
	}
	defer manager.Close()

	if dynamic {
		return backendxdp.ClearBlacklistMap(manager.DynamicBlacklist())
	}
	return backendxdp.ClearBlacklistMap(manager.StaticBlacklist())
}

// CleanupExpiredPinned removes expired entries from pinned blacklist, whitelist,
// and IP-port rule maps.
func CleanupExpiredPinned(pinPath string, log *zap.SugaredLogger) (ExpiredCleanupSummary, error) {
	manager, err := datapathprograms.OpenPinnedManager(pinPath, log)
	if err != nil {
		return ExpiredCleanupSummary{}, err
	}
	defer manager.Close()

	locked, _ := backendxdp.CleanupExpiredRules(manager.StaticBlacklist(), false)
	whitelist, _ := backendxdp.CleanupExpiredRules(manager.Whitelist(), false)
	ipPort, _ := backendxdp.CleanupExpiredRules(manager.RuleMap(), false)

	return ExpiredCleanupSummary{
		Locked:    locked,
		Whitelist: whitelist,
		IPPort:    ipPort,
	}, nil
}
