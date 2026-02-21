package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"

	"github.com/netxfw/netxfw/internal/config"
	"github.com/netxfw/netxfw/internal/plugins/types"
	"github.com/netxfw/netxfw/internal/utils/iputil"
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
	pass, drop, _ := s.sdk.Stats.GetCounters()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]uint64{
		"pass": pass,
		"drop": drop,
	})
}

// handleRules provides a REST interface for listing, adding, and removing BPF rules.
// handleRules 提供用于列出、添加和移除 BPF 规则的 REST 接口。
func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet:
		search := r.URL.Query().Get("search")
		limit := 100

		locked, totalLocked, _ := s.sdk.Blacklist.List(limit, search)
		whitelist, totalWhitelist, _ := s.sdk.Whitelist.List(limit, search)

		// Get IP+Port rules (action 1=allow, 2=deny)
		// 获取 IP+端口规则（action 1=允许, 2=拒绝）
		ipPortRules, totalIPPort, _ := s.sdk.Rule.List(true, limit, search)

		res := map[string]any{
			"blacklist":      locked,
			"totalBlacklist": totalLocked,
			"whitelist":      whitelist,
			"totalWhitelist": totalWhitelist,
			"ipPortRules":    ipPortRules,
			"totalIPPort":    totalIPPort,
			"limit":          limit,
		}
		_ = json.NewEncoder(w).Encode(res)

	case http.MethodPost:
		var req struct {
			Type   string `json:"type"`   // "blacklist" or "whitelist" / "blacklist" 或 "whitelist"
			Action string `json:"action"` // "add" or "remove" / "add" 或 "remove"
			CIDR   string `json:"cidr"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		var err error
		if req.Action == "add" {
			if req.Type == "blacklist" {
				err = s.sdk.Blacklist.Add(req.CIDR)
			} else if req.Type == "whitelist" {
				port := uint16(0)
				// Parse optional port (e.g. 1.2.3.4:80 or [::1]:80)
				// 解析可选端口（例如 1.2.3.4:80 或 [::1]:80）
				host, pVal, pErr := iputil.ParseIPPort(req.CIDR)
				if pErr == nil {
					req.CIDR = host
					port = pVal
				}

				if port > 0 {
					err = s.sdk.Whitelist.AddWithPort(req.CIDR, port)
				} else {
					err = s.sdk.Whitelist.Add(req.CIDR, 0)
				}
			} else if req.Type == "ip_port_rules" {
				ipStr, port, action, parseErr := parseIPPortAction(req.CIDR)
				if parseErr != nil {
					err = parseErr
				} else {
					ipNet, err2 := iputil.ParseCIDR(ipStr)

					if err2 != nil {
						err = err2
					}

					if err == nil {
						err = s.sdk.Rule.Add(ipNet.String(), port, action)
					}
				}
			}
		} else {
			if req.Type == "ip_port_rules" {
				ipStr, port, _, parseErr := parseIPPortAction(req.CIDR)
				if parseErr != nil {
					err = parseErr
				} else {
					ipNet, err2 := iputil.ParseCIDR(ipStr)
					if err2 != nil {
						err = err2
					}
					if err == nil {
						err = s.sdk.Rule.Remove(ipNet.String(), port)
					}
				}
			} else if req.Type == "blacklist" {
				err = s.sdk.Blacklist.Remove(req.CIDR)
			} else if req.Type == "whitelist" {
				err = s.sdk.Whitelist.Remove(req.CIDR)
			}
		}

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
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

// handleSync triggers synchronization between BPF maps and configuration files.
func (s *Server) handleSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Direction string `json:"direction"` // "map2file" or "file2map"
		Mode      string `json:"mode"`      // "incremental" or "overwrite"
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Use the config manager to load the configuration
	cfgManager := config.GetConfigManager()
	err := cfgManager.LoadConfig()
	if err != nil {
		http.Error(w, "Failed to load config: "+err.Error(), http.StatusInternalServerError)
		return
	}

	cfg := cfgManager.GetConfig()
	if cfg == nil {
		http.Error(w, "Failed to get config from manager", http.StatusInternalServerError)
		return
	}

	if req.Direction == "map2file" {
		types.ConfigMu.Lock()
		// Reload config using the config manager inside lock to ensure freshness before writing back
		// 在锁内使用配置管理器重新加载配置，以确保在写回之前的新鲜度
		err = cfgManager.LoadConfig()
		if err != nil {
			types.ConfigMu.Unlock()
			http.Error(w, "Failed to reload config: "+err.Error(), http.StatusInternalServerError)
			return
		}
		cfg = cfgManager.GetConfig()
		if cfg == nil {
			types.ConfigMu.Unlock()
			http.Error(w, "Failed to get config from manager", http.StatusInternalServerError)
			return
		}

		err = s.sdk.Sync.ToConfig(cfg)
		if err == nil {
			// Update config in manager and save using the manager
			cfgManager.UpdateConfig(cfg)
			err = cfgManager.SaveConfig()
		}
		types.ConfigMu.Unlock()
	} else {
		// For file2map, we just loaded the config (snapshot).
		// Even if file changes now, we apply this snapshot.
		// 对于 file2map，我们刚刚加载了配置（快照）。
		// 即使文件现在发生变化，我们也应用此快照。
		overwrite := req.Mode == "overwrite"
		err = s.sdk.Sync.ToMap(cfg, overwrite)
	}

	if err != nil {
		http.Error(w, "Sync failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"status":"ok"}`)
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
