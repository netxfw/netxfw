package api

import (
	"encoding/json"
	"net/http"
)

// handlePerfStats returns all performance statistics.
// handlePerfStats 返回所有性能统计信息。
func (s *Server) handlePerfStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	perfStats := s.sdk.GetManager().PerfStats()
	if perfStats == nil {
		http.Error(w, "Performance stats not available", http.StatusServiceUnavailable)
		return
	}

	_ = json.NewEncoder(w).Encode(perfStats)
}

// handlePerfLatency returns map operation latency statistics.
// handlePerfLatency 返回 Map 操作延迟统计信息。
func (s *Server) handlePerfLatency(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	perfStats := s.sdk.GetManager().PerfStats()
	if perfStats == nil {
		http.Error(w, "Performance stats not available", http.StatusServiceUnavailable)
		return
	}

	stats, ok := perfStats.(interface {
		GetLatencyStats() interface{}
	})
	if !ok {
		http.Error(w, "Latency stats not available", http.StatusServiceUnavailable)
		return
	}

	_ = json.NewEncoder(w).Encode(stats.GetLatencyStats())
}

// handlePerfCache returns cache hit rate statistics.
// handlePerfCache 返回缓存命中率统计信息。
func (s *Server) handlePerfCache(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	perfStats := s.sdk.GetManager().PerfStats()
	if perfStats == nil {
		http.Error(w, "Performance stats not available", http.StatusServiceUnavailable)
		return
	}

	stats, ok := perfStats.(interface {
		GetCacheStats() interface{}
	})
	if !ok {
		http.Error(w, "Cache stats not available", http.StatusServiceUnavailable)
		return
	}

	_ = json.NewEncoder(w).Encode(stats.GetCacheStats())
}

// handlePerfTraffic returns real-time traffic statistics.
// handlePerfTraffic 返回实时流量统计信息。
func (s *Server) handlePerfTraffic(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	perfStats := s.sdk.GetManager().PerfStats()
	if perfStats == nil {
		http.Error(w, "Performance stats not available", http.StatusServiceUnavailable)
		return
	}

	stats, ok := perfStats.(interface {
		GetTrafficStats() interface{}
	})
	if !ok {
		http.Error(w, "Traffic stats not available", http.StatusServiceUnavailable)
		return
	}

	_ = json.NewEncoder(w).Encode(stats.GetTrafficStats())
}

// handlePerfReset resets performance statistics counters.
// handlePerfReset 重置性能统计计数器。
func (s *Server) handlePerfReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	perfStats := s.sdk.GetManager().PerfStats()
	if perfStats == nil {
		http.Error(w, "Performance stats not available", http.StatusServiceUnavailable)
		return
	}

	stats, ok := perfStats.(interface {
		Reset()
	})
	if !ok {
		http.Error(w, "Reset not available", http.StatusServiceUnavailable)
		return
	}

	stats.Reset()

	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":  "ok",
		"message": "Performance statistics reset successfully",
	})
}
