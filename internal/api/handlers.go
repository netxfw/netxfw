package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"

	"github.com/netxfw/netxfw/internal/version"
)

// handleHealthz returns the health status of the service.
// handleHealthz 返回服务的健康状态。
func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status": "ok",
	})
}

// handleVersion returns the version information of the service.
// handleVersion 返回服务的版本信息。
func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"version": version.Version,
	})
}

// handleStats returns the global pass/drop statistics.
// handleStats 返回全局放行/拦截统计信息。
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	globalStats, err := s.sdk.Stats.GetGlobalStats()
	if err != nil {
		http.Error(w, "Failed to get statistics: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	res := statsResponse{
		Packets: packetStats{
			Total:   globalStats.TotalPackets,
			Passed:  globalStats.TotalPass,
			Dropped: globalStats.TotalDrop,
		},
		DropReasons: dropReasonStats{
			Blacklist:   globalStats.DropBlacklist,
			NoRule:      globalStats.DropNoRule,
			Invalid:     globalStats.DropInvalid,
			RateLimit:   globalStats.DropRateLimit,
			SynFlood:    globalStats.DropSynFlood,
			IcmpLimit:   globalStats.DropIcmpLimit,
			PortBlocked: globalStats.DropPortBlocked,
			DefaultDeny: globalStats.DropDefaultDeny,
		},
		PassReasons: passReasonStats{
			Whitelist:   globalStats.PassWhitelist,
			Rule:        globalStats.PassRule,
			Return:      globalStats.PassReturn,
			Established: globalStats.PassEstablished,
		},
	}
	_ = json.NewEncoder(w).Encode(res)
}

// handleConfig updates runtime configuration parameters.
// handleConfig 更新运行时配置参数。
func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var req struct {
			Key   string `json:"key"`
			Value bool   `json:"value"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		var err error
		switch req.Key {
		case "afxdp":
			err = s.sdk.Security.SetEnableAFXDP(req.Value)
		case "default_deny":
			err = s.sdk.Security.SetDefaultDeny(req.Value)
		}

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	w.WriteHeader(http.StatusOK)
}

// handleConntrack returns the list of active network connections.
func (s *Server) handleConntrack(w http.ResponseWriter, r *http.Request) {
	entries, err := s.sdk.Conntrack.List()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].LastSeen.After(entries[j].LastSeen)
	})

	total := len(entries)
	limit := 20
	if total < limit {
		limit = total
	}

	topEntries := entries[:limit]

	res := map[string]any{
		"total": total,
		"top":   topEntries,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}

func (s *Server) handleUI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, uiHTML)
}
