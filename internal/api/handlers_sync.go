package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	appconfig "github.com/netxfw/netxfw/internal/app/config"
	domainconfig "github.com/netxfw/netxfw/internal/domain/config"
	"github.com/netxfw/netxfw/internal/ports"
)

// handleSync triggers synchronization between BPF maps and configuration files.
func (s *Server) handleSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Direction string `json:"direction"`
		Mode      string `json:"mode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	cfg, err := appconfig.LoadConfig()
	if err != nil {
		http.Error(w, "Failed to load config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if cfg == nil {
		http.Error(w, "Failed to get config snapshot", http.StatusInternalServerError)
		return
	}

	if req.Direction == "map2file" {
		err = appconfig.MutateLoadedConfig(func(cfg *domainconfig.Config) error {
			return s.sdk.Sync.ToConfig(ports.ConfigToSDK(cfg))
		})
	} else {
		overwrite := req.Mode == "overwrite"
		err = s.sdk.Sync.ToMap(ports.ConfigToSDK(cfg), overwrite)
	}

	if err != nil {
		http.Error(w, "Sync failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, `{"status":"ok"}`)
}
