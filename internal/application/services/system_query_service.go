package services

import (
	"time"

	"github.com/netxfw/netxfw/internal/app"
	"github.com/netxfw/netxfw/internal/xdp"
	"github.com/netxfw/netxfw/pkg/sdk"
)

// TrafficStats is the query-layer alias for runtime traffic statistics.
type TrafficStats = app.TrafficStats

// InterfaceXDPInfo is the query-layer alias for XDP attachment details.
type InterfaceXDPInfo = xdp.InterfaceXDPInfo

// SystemQueryService centralizes read-only system queries for CLI display.
type SystemQueryService struct{}

func NewSystemQueryService() *SystemQueryService {
	return &SystemQueryService{}
}

func (s *SystemQueryService) LoadConfig() (*sdk.GlobalConfig, error) {
	return app.LoadConfig()
}

func (s *SystemQueryService) LoadTrafficStats() (TrafficStats, error) {
	return app.LoadTrafficStats()
}

func (s *SystemQueryService) GetAttachedInterfaceInfos() ([]InterfaceXDPInfo, error) {
	return app.GetAttachedInterfaceInfos()
}

func (s *SystemQueryService) GetConntrackMax() int {
	return app.GetConntrackMax()
}

func (s *SystemQueryService) FormatNumberWithComma(n uint64) string {
	return app.FormatNumberWithComma(n)
}

func (s *SystemQueryService) FormatBPS(bps uint64) string {
	return app.FormatBPS(bps)
}

func (s *SystemQueryService) FormatDuration(d time.Duration) string {
	return app.FormatDuration(d)
}
