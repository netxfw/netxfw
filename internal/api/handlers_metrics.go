package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/livp123/netxfw/internal/xdp"
	"github.com/livp123/netxfw/pkg/sdk"
)

// MetricsHandler handles metrics API requests.
// MetricsHandler 处理指标 API 请求。
type MetricsHandler struct {
	sdk *sdk.SDK
}

// NewMetricsHandler creates a new metrics handler.
// NewMetricsHandler 创建新的指标处理器。
func NewMetricsHandler(s *sdk.SDK) *MetricsHandler {
	return &MetricsHandler{
		sdk: s,
	}
}

// RegisterMetricsRoutes registers metrics API routes to the server's mux.
// RegisterMetricsRoutes 注册指标 API 路由到服务器的 mux。
func RegisterMetricsRoutes(mux *http.ServeMux, s *sdk.SDK) {
	handler := NewMetricsHandler(s)
	mux.HandleFunc("/api/v1/metrics", handler.HandleMetrics)
	mux.HandleFunc("/api/v1/metrics/traffic", handler.HandleTrafficMetrics)
	mux.HandleFunc("/api/v1/metrics/conntrack", handler.HandleConntrackHealth)
	mux.HandleFunc("/api/v1/metrics/maps", handler.HandleMapUsage)
	mux.HandleFunc("/api/v1/metrics/ratelimit", handler.HandleRateLimitStats)
	mux.HandleFunc("/api/v1/metrics/protocols", handler.HandleProtocolStats)
}

// getManager extracts the xdp.Manager from the SDK.
// getManager 从 SDK 中提取 xdp.Manager。
func (h *MetricsHandler) getManager() *xdp.Manager {
	if h.sdk == nil {
		return nil
	}

	mgr := h.sdk.GetManager()
	if mgr == nil {
		return nil
	}

	// Try to get Manager from Adapter / 尝试从 Adapter 获取 Manager
	if adapter, ok := mgr.(*xdp.Adapter); ok {
		return adapter.GetManager()
	}

	return nil
}

// HandleMetrics handles full metrics request.
// HandleMetrics 处理完整指标请求。
func (h *MetricsHandler) HandleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	manager := h.getManager()
	if manager == nil {
		http.Error(w, "Manager not available", http.StatusServiceUnavailable)
		return
	}

	collector := xdp.NewMetricsCollector(manager)
	if err := collector.Collect(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	metrics := collector.GetMetrics()
	writeJSONResponse(w, metrics)
}

// HandleTrafficMetrics handles traffic metrics request (PPS/BPS).
// HandleTrafficMetrics 处理流量指标请求 (PPS/BPS)。
func (h *MetricsHandler) HandleTrafficMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	manager := h.getManager()
	if manager == nil {
		http.Error(w, "Manager not available", http.StatusServiceUnavailable)
		return
	}

	collector := xdp.NewMetricsCollector(manager)
	if err := collector.Collect(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	metrics := collector.GetTrafficMetrics()
	writeJSONResponse(w, metrics)
}

// HandleConntrackHealth handles conntrack health request.
// HandleConntrackHealth 处理连接跟踪健康度请求。
func (h *MetricsHandler) HandleConntrackHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	manager := h.getManager()
	if manager == nil {
		http.Error(w, "Manager not available", http.StatusServiceUnavailable)
		return
	}

	collector := xdp.NewMetricsCollector(manager)
	if err := collector.Collect(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	health := collector.GetConntrackHealth()
	writeJSONResponse(w, health)
}

// HandleMapUsage handles map usage statistics request.
// HandleMapUsage 处理 Map 使用率统计请求。
func (h *MetricsHandler) HandleMapUsage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	manager := h.getManager()
	if manager == nil {
		http.Error(w, "Manager not available", http.StatusServiceUnavailable)
		return
	}

	collector := xdp.NewMetricsCollector(manager)
	if err := collector.Collect(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	usage := collector.GetMapUsage()
	writeJSONResponse(w, usage)
}

// HandleRateLimitStats handles rate limit statistics request.
// HandleRateLimitStats 处理限速统计请求。
func (h *MetricsHandler) HandleRateLimitStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	manager := h.getManager()
	if manager == nil {
		http.Error(w, "Manager not available", http.StatusServiceUnavailable)
		return
	}

	collector := xdp.NewMetricsCollector(manager)
	if err := collector.Collect(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	stats := collector.GetRateLimitStats()
	writeJSONResponse(w, stats)
}

// HandleProtocolStats handles protocol distribution request.
// HandleProtocolStats 处理协议分布请求。
func (h *MetricsHandler) HandleProtocolStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	manager := h.getManager()
	if manager == nil {
		http.Error(w, "Manager not available", http.StatusServiceUnavailable)
		return
	}

	collector := xdp.NewMetricsCollector(manager)
	if err := collector.Collect(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	stats := collector.GetProtocolStats()
	writeJSONResponse(w, stats)
}

// MetricsSummary represents a summary of all metrics.
// MetricsSummary 表示所有指标的摘要。
type MetricsSummary struct {
	Timestamp time.Time `json:"timestamp"`
	Uptime    string    `json:"uptime"`

	// Traffic summary / 流量摘要
	Traffic TrafficSummary `json:"traffic"`

	// Conntrack summary / 连接跟踪摘要
	Conntrack ConntrackSummary `json:"conntrack"`

	// Map usage summary / Map 使用率摘要
	Maps MapSummary `json:"maps"`

	// Protocol summary / 协议摘要
	Protocols ProtocolSummary `json:"protocols"`
}

// TrafficSummary represents traffic metrics summary.
// TrafficSummary 表示流量指标摘要。
type TrafficSummary struct {
	CurrentPPS uint64 `json:"current_pps"`
	CurrentBPS uint64 `json:"current_bps"`
	PeakPPS    uint64 `json:"peak_pps"`
	PeakBPS    uint64 `json:"peak_bps"`
	DropRate   string `json:"drop_rate"`
	PassRate   string `json:"pass_rate"`
}

// ConntrackSummary represents conntrack health summary.
// ConntrackSummary 表示连接跟踪健康度摘要。
type ConntrackSummary struct {
	Entries    int    `json:"entries"`
	MaxEntries int    `json:"max_entries"`
	UsagePct   int    `json:"usage_pct"`
	Status     string `json:"status"`
	TCPCount   uint64 `json:"tcp_count"`
	UDPCount   uint64 `json:"udp_count"`
	ICMPCount  uint64 `json:"icmp_count"`
	OtherCount uint64 `json:"other_count"`
}

// MapSummary represents map usage summary.
// MapSummary 表示 Map 使用率摘要。
type MapSummary struct {
	TotalMaps    int `json:"total_maps"`
	HealthyMaps  int `json:"healthy_maps"`
	WarningMaps  int `json:"warning_maps"`
	CriticalMaps int `json:"critical_maps"`
	OverallUsage int `json:"overall_usage"`
}

// ProtocolSummary represents protocol distribution summary.
// ProtocolSummary 表示协议分布摘要。
type ProtocolSummary struct {
	TCP   string `json:"tcp"`
	UDP   string `json:"udp"`
	ICMP  string `json:"icmp"`
	Other string `json:"other"`
}

// writeJSONResponse writes JSON response.
// writeJSONResponse 写入 JSON 响应。
func writeJSONResponse(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	encoder.Encode(data)
}
