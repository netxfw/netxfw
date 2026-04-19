package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"sync"

	appconfig "github.com/netxfw/netxfw/internal/app/config"
	"github.com/netxfw/netxfw/internal/utils/iputil"
	"github.com/netxfw/netxfw/internal/version"
	"github.com/netxfw/netxfw/pkg/sdk"
)

type packetStats struct {
	Total   uint64 `json:"total"`
	Passed  uint64 `json:"passed"`
	Dropped uint64 `json:"dropped"`
}

type dropReasonStats struct {
	Blacklist   uint64 `json:"blacklist"`
	NoRule      uint64 `json:"no_rule"`
	Invalid     uint64 `json:"invalid"`
	RateLimit   uint64 `json:"rate_limit"`
	SynFlood    uint64 `json:"syn_flood"`
	IcmpLimit   uint64 `json:"icmp_limit"`
	PortBlocked uint64 `json:"port_blocked"`
	DefaultDeny uint64 `json:"default_deny"`
}

type passReasonStats struct {
	Whitelist   uint64 `json:"whitelist"`
	Rule        uint64 `json:"rule"`
	Return      uint64 `json:"return"`
	Established uint64 `json:"established"`
}

type statsResponse struct {
	Packets     packetStats     `json:"packets"`
	DropReasons dropReasonStats `json:"drop_reasons"`
	PassReasons passReasonStats `json:"pass_reasons"`
}

type rulesResponse struct {
	Blacklist      []sdk.BlockedIP  `json:"blacklist"`
	TotalBlacklist int              `json:"totalBlacklist"`
	Whitelist      []string         `json:"whitelist"`
	TotalWhitelist int              `json:"totalWhitelist"`
	IPPortRules    []sdk.IPPortRule `json:"ipPortRules"`
	TotalIPPort    int              `json:"totalIPPort"`
	Limit          int              `json:"limit"`
}

const (
	ruleTypeBlacklist = "blacklist"
	ruleTypeWhitelist = "whitelist"
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

// handleRules provides a REST interface for listing, adding, and removing BPF rules.
// handleRules 提供用于列出、添加和移除 BPF 规则的 REST 接口。
//
//nolint:gocyclo // HTTP handler stays inline so behavior changes stay localized.
func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet:
		search := r.URL.Query().Get("search")
		limit := 100

		var wg sync.WaitGroup
		wg.Add(3)
		errCh := make(chan error, 3)

		var locked []sdk.BlockedIP
		var totalLocked int
		var whitelist []string
		var totalWhitelist int
		var ipPortRules []sdk.IPPortRule
		var totalIPPort int

		go func() {
			defer wg.Done()
			var err error
			locked, totalLocked, err = s.sdk.Blacklist.List(limit, search)
			if err != nil {
				errCh <- err
			}
		}()

		go func() {
			defer wg.Done()
			var err error
			whitelist, totalWhitelist, err = s.sdk.Whitelist.List(limit, search)
			if err != nil {
				errCh <- err
			}
		}()

		go func() {
			defer wg.Done()
			var err error
			ipPortRules, totalIPPort, err = s.sdk.Rule.List(true, limit, search)
			if err != nil {
				errCh <- err
			}
		}()

		wg.Wait()
		close(errCh)
		for err := range errCh {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		res := rulesResponse{
			Blacklist:      locked,
			TotalBlacklist: totalLocked,
			Whitelist:      whitelist,
			TotalWhitelist: totalWhitelist,
			IPPortRules:    ipPortRules,
			TotalIPPort:    totalIPPort,
			Limit:          limit,
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
		switch req.Action {
		case "add":
			switch req.Type {
			case ruleTypeBlacklist:
				err = s.sdk.Blacklist.Add(req.CIDR)
			case ruleTypeWhitelist:
				port := uint16(0)
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
			case "ip_port_rules":
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
			default:
				http.Error(w, "invalid type", http.StatusBadRequest)
				return
			}
		case "remove":
			switch req.Type {
			case "ip_port_rules":
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
			case ruleTypeBlacklist:
				err = s.sdk.Blacklist.Remove(req.CIDR)
			case ruleTypeWhitelist:
				err = s.sdk.Whitelist.Remove(req.CIDR)
			default:
				http.Error(w, "invalid type", http.StatusBadRequest)
				return
			}
		case "clear":
			switch req.Type {
			case ruleTypeBlacklist:
				err = s.sdk.Blacklist.Clear()
			case ruleTypeWhitelist:
				err = s.sdk.Whitelist.Clear()
			default:
				http.Error(w, "invalid type", http.StatusBadRequest)
				return
			}
		default:
			http.Error(w, "invalid action", http.StatusBadRequest)
			return
		}

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
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
		err = appconfig.MutateLoadedConfig(func(cfg *sdk.GlobalConfig) error {
			// Sync runtime state into this config snapshot, then persist.
			return s.sdk.Sync.ToConfig(cfg)
		})
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
