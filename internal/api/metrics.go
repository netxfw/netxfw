package api

import (
	"github.com/netxfw/netxfw/internal/metrics/exporter"
	"github.com/netxfw/netxfw/internal/plugins/types"
	"github.com/netxfw/netxfw/pkg/sdk"
)

// MetricsServer represents the metrics server.
// MetricsServer 代表指标服务器。
type MetricsServer = exporter.Server

// NewMetricsServer creates a new metrics server instance.
// NewMetricsServer 创建一个新的指标服务器实例。
func NewMetricsServer(s *sdk.SDK, config *types.MetricsConfig) *MetricsServer {
	return exporter.NewServer(s, config)
}
