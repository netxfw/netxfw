package services

import (
	"github.com/netxfw/netxfw/internal/app"
	"github.com/netxfw/netxfw/pkg/sdk"
)

// PerformanceStats is the query-layer alias for performance statistics.
type PerformanceStats = app.PerformanceStats

// OperationStats is the query-layer alias for operation statistics.
type OperationStats = app.OperationStats

// PerformanceQueryService centralizes read-only perf/stat formatting for CLI.
type PerformanceQueryService struct{}

func NewPerformanceQueryService() *PerformanceQueryService {
	return &PerformanceQueryService{}
}

func (s *PerformanceQueryService) LoadPerformanceStats(mgr sdk.ManagerInterface) (*PerformanceStats, error) {
	return app.LoadPerformanceStats(mgr)
}

func (s *PerformanceQueryService) FormatLatency(ns uint64) string {
	return app.FormatLatency(ns)
}

func (s *PerformanceQueryService) FormatNumber(n uint64) string {
	return app.FormatNumber(n)
}

func (s *PerformanceQueryService) FormatBytes(b uint64) string {
	return app.FormatBytes(b)
}
