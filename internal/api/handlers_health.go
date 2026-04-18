package api

import (
	"encoding/json"
	"net/http"

	datapathhealth "github.com/netxfw/netxfw/internal/datapath/xdp/health"
)

// handleHealth returns the health status of the service including BPF maps.
// handleHealth 返回服务健康状态，包括 BPF Map 状态。
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if s.sdk == nil {
		http.Error(w, "Manager not available", http.StatusServiceUnavailable)
		return
	}

	mgr := s.sdk.GetManager()
	if mgr == nil {
		http.Error(w, "Manager not available", http.StatusServiceUnavailable)
		return
	}

	healthStatus, err := datapathhealth.LoadStatus(mgr)
	if err != nil {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  "ok",
			"message": "Basic health check passed",
		})
		return
	}
	_ = json.NewEncoder(w).Encode(healthStatus)
}

// handleHealthMaps returns the health status of all BPF maps.
// handleHealthMaps 返回所有 BPF Map 的健康状态。
func (s *Server) handleHealthMaps(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if s.sdk == nil {
		http.Error(w, "Manager not available", http.StatusServiceUnavailable)
		return
	}

	mgr := s.sdk.GetManager()
	if mgr == nil {
		http.Error(w, "Manager not available", http.StatusServiceUnavailable)
		return
	}

	healthStatus, err := datapathhealth.LoadStatus(mgr)
	if err != nil {
		http.Error(w, "Health checking not supported", http.StatusNotImplemented)
		return
	}
	_ = json.NewEncoder(w).Encode(healthStatus.BPFMaps)
}

// handleHealthMap returns the health status of a specific BPF map.
// handleHealthMap 返回特定 BPF Map 的健康状态。
func (s *Server) handleHealthMap(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	mapName := r.URL.Query().Get("name")
	if mapName == "" {
		http.Error(w, "Map name required", http.StatusBadRequest)
		return
	}

	if s.sdk == nil {
		http.Error(w, "Manager not available", http.StatusServiceUnavailable)
		return
	}

	mgr := s.sdk.GetManager()
	if mgr == nil {
		http.Error(w, "Manager not available", http.StatusServiceUnavailable)
		return
	}

	checker := datapathhealth.CheckerFromManager(mgr)
	if checker == nil {
		http.Error(w, "Health checking not supported", http.StatusNotImplemented)
		return
	}

	mapStatus, err := checker.CheckMapHealth(mapName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	_ = json.NewEncoder(w).Encode(mapStatus)
}
