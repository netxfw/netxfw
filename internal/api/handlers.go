package api

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/internal/xdp"
)

// handleStats returns the global pass/drop statistics.
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	pass, drop := s.manager.GetStats()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]uint64{
		"pass": pass,
		"drop": drop,
	})
}

// handleRules provides a REST interface for listing, adding, and removing BPF rules.
func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet:
		search := r.URL.Query().Get("search")
		limit := 100

		locked, totalLocked, _ := xdp.ListBlockedIPs(s.manager.LockList(), false, limit, search)
		whitelist, totalWhitelist, _ := xdp.ListBlockedIPs(s.manager.Whitelist(), false, limit, search)

		// Get IP+Port rules (action 1=allow, 2=deny)
		ipPortRules, totalIPPort, _ := s.manager.ListIPPortRules(false, limit, search)

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
		// Check cluster mode
		cfgCheck, _ := types.LoadGlobalConfig(s.configPath)
		if cfgCheck != nil && cfgCheck.Cluster.Enabled {
			http.Error(w, "Write operations forbidden in cluster mode", http.StatusForbidden)
			return
		}

		var req struct {
			Type   string `json:"type"`   // "blacklist" or "whitelist"
			Action string `json:"action"` // "add" or "remove"
			CIDR   string `json:"cidr"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		var err error
		var m *ebpf.Map
		if req.Action == "add" {
			if req.Type == "blacklist" {
				m = s.manager.LockList()
				err = xdp.LockIP(m, req.CIDR)
			} else if req.Type == "whitelist" {
				port := uint16(0)
				cidr := req.CIDR
				if strings.Contains(cidr, ":") && !strings.Contains(cidr, "[") && !strings.Contains(cidr, "/") && strings.Count(cidr, ":") == 1 {
					parts := strings.Split(cidr, ":")
					cidr = parts[0]
					fmt.Sscanf(parts[1], "%d", &port)
				}

				m = s.manager.Whitelist()
				err = xdp.AllowIP(m, cidr, port)
			} else if req.Type == "ip_port_rules" {
				ipStr, port, action, parseErr := parseIPPortAction(req.CIDR)
				if parseErr != nil {
					err = parseErr
				} else {
					_, ipNet, err2 := net.ParseCIDR(ipStr)
					if err2 != nil {
						parsedIP := net.ParseIP(ipStr)
						if parsedIP == nil {
							err = fmt.Errorf("invalid IP: %s", ipStr)
						} else {
							mask := net.CIDRMask(32, 32)
							if parsedIP.To4() == nil {
								mask = net.CIDRMask(128, 128)
							}
							ipNet = &net.IPNet{IP: parsedIP, Mask: mask}
						}
					}

					if err == nil {
						err = s.manager.AddIPPortRule(ipNet, port, action, nil)
					}
				}
			}
		} else {
			if req.Type == "ip_port_rules" {
				ipStr, port, _, parseErr := parseIPPortAction(req.CIDR)
				if parseErr != nil {
					err = parseErr
				} else {
					_, ipNet, err2 := net.ParseCIDR(ipStr)
					if err2 != nil {
						parsedIP := net.ParseIP(ipStr)
						if parsedIP == nil {
							err = fmt.Errorf("invalid IP: %s", ipStr)
						} else {
							mask := net.CIDRMask(32, 32)
							if parsedIP.To4() == nil {
								mask = net.CIDRMask(128, 128)
							}
							ipNet = &net.IPNet{IP: parsedIP, Mask: mask}
						}
					}

					if err == nil {
						err = s.manager.RemoveIPPortRule(ipNet, port)
					}
				}
			} else {
				if req.Type == "blacklist" {
					m = s.manager.LockList()
				} else {
					m = s.manager.Whitelist()
				}
				err = xdp.UnlockIP(m, req.CIDR)
			}
		}

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Persistence logic
		cfg, _ := types.LoadGlobalConfig(s.configPath)
		if cfg != nil && cfg.Base.PersistRules {
			if req.Type == "blacklist" {
				if req.Action == "add" {
					appendToFile(cfg.Base.LockListFile, req.CIDR)
				} else {
					removeFromFile(cfg.Base.LockListFile, req.CIDR)
				}
			} else if req.Type == "whitelist" {
				if req.Action == "add" {
					found := false
					for _, item := range cfg.Base.Whitelist {
						if item == req.CIDR {
							found = true
							break
						}
					}
					if !found {
						cfg.Base.Whitelist = append(cfg.Base.Whitelist, req.CIDR)
						types.SaveGlobalConfig(s.configPath, cfg)
					}
				} else {
					newWL := []string{}
					for _, item := range cfg.Base.Whitelist {
						if item != req.CIDR {
							newWL = append(newWL, item)
						}
					}
					cfg.Base.Whitelist = newWL
					types.SaveGlobalConfig(s.configPath, cfg)
				}
			} else if req.Type == "ip_port_rules" {
				ipStr, port, action, parseErr := parseIPPortAction(req.CIDR)
				if parseErr == nil {
					if req.Action == "add" {
						found := false
						for i, rule := range cfg.Port.IPPortRules {
							if rule.IP == ipStr && rule.Port == port {
								cfg.Port.IPPortRules[i].Action = action
								found = true
								break
							}
						}
						if !found {
							cfg.Port.IPPortRules = append(cfg.Port.IPPortRules, types.IPPortRule{
								IP:     ipStr,
								Port:   port,
								Action: action,
							})
						}
					} else {
						newRules := []types.IPPortRule{}
						for _, rule := range cfg.Port.IPPortRules {
							if rule.IP != ipStr || rule.Port != port {
								newRules = append(newRules, rule)
							}
						}
						cfg.Port.IPPortRules = newRules
					}
					types.SaveGlobalConfig(s.configPath, cfg)
				}
			}
		}

		w.WriteHeader(http.StatusOK)
	}
}

// handleConfig updates runtime configuration parameters.
func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		// Check cluster mode
		cfgCheck, _ := types.LoadGlobalConfig(s.configPath)
		if cfgCheck != nil && cfgCheck.Cluster.Enabled {
			http.Error(w, "Write operations forbidden in cluster mode", http.StatusForbidden)
			return
		}

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
			err = s.manager.SetEnableAFXDP(req.Value)
		case "default_deny":
			err = s.manager.SetDefaultDeny(req.Value)
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
		err = s.manager.SyncToFiles(cfg)
		if err == nil {
			err = types.SaveGlobalConfig(s.configPath, cfg)
		}
	} else {
		overwrite := req.Mode == "overwrite"
		err = s.manager.SyncFromFiles(cfg, overwrite)
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
	entries, err := s.manager.ListConntrackEntries()
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
