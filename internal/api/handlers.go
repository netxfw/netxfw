package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"

	"github.com/livp123/netxfw/internal/core"
	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/internal/utils/iputil"
)

// handleStats returns the global pass/drop statistics.
// handleStats 返回全局放行/拦截统计信息。
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	pass, drop, _ := s.sdk.Stats.GetCounters()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]uint64{
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

		res := map[string]interface{}{
			"blacklist":      locked,
			"totalBlacklist": totalLocked,
			"whitelist":      whitelist,
			"totalWhitelist": totalWhitelist,
			"ipPortRules":    ipPortRules,
			"totalIPPort":    totalIPPort,
			"limit":          limit,
		}
		json.NewEncoder(w).Encode(res)

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
			err = core.SyncEnableAFXDP(r.Context(), s.sdk.GetManager(), req.Value)
		case "default_deny":
			err = core.SyncDefaultDeny(r.Context(), s.sdk.GetManager(), req.Value)
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

	cfg, err := types.LoadGlobalConfig(s.configPath)
	if err != nil {
		http.Error(w, "Failed to load config: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if req.Direction == "map2file" {
		types.ConfigMu.Lock()
		// Reload config inside lock to ensure freshness before writing back
		// 在锁内重新加载配置，以确保在写回之前的新鲜度
		cfg, err = types.LoadGlobalConfig(s.configPath)
		if err != nil {
			types.ConfigMu.Unlock()
			http.Error(w, "Failed to load config: "+err.Error(), http.StatusInternalServerError)
			return
		}

		err = s.sdk.GetManager().SyncToFiles(cfg)
		if err == nil {
			err = types.SaveGlobalConfig(s.configPath, cfg)
		}
		types.ConfigMu.Unlock()
	} else {
		// For file2map, we just loaded the config (snapshot).
		// Even if file changes now, we apply this snapshot.
		// 对于 file2map，我们刚刚加载了配置（快照）。
		// 即使文件现在发生变化，我们也应用此快照。
		overwrite := req.Mode == "overwrite"
		err = s.sdk.GetManager().SyncFromFiles(cfg, overwrite)
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
	// TODO: Add Conntrack API to SDK
	entries, err := s.sdk.GetManager().ListAllConntrackEntries()
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

	res := map[string]interface{}{
		"total": total,
		"top":   topEntries,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

func (s *Server) handleUI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, uiHTML)
}
