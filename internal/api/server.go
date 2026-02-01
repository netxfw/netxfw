package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/internal/xdp"
)

type Server struct {
	manager *xdp.Manager
	port    int
	configPath string
}

func NewServer(manager *xdp.Manager, port int) *Server {
	return &Server{
		manager:    manager,
		port:       port,
		configPath: "/etc/netxfw/config.yaml",
	}
}

func (s *Server) Start() error {
	mux := http.NewServeMux()

	// API Endpoints
	mux.HandleFunc("/api/stats", s.handleStats)
	mux.HandleFunc("/api/rules", s.handleRules)
	mux.HandleFunc("/api/config", s.handleConfig)
	mux.HandleFunc("/api/sync", s.handleSync)

	// UI (Embedded)
	mux.HandleFunc("/", s.handleUI)

	addr := fmt.Sprintf(":%d", s.port)
	log.Printf("🚀 Management API and UI starting on http://localhost%s", addr)
	return http.ListenAndServe(addr, mux)
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	pass, drop := s.manager.GetStats()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]uint64{
		"pass": pass,
		"drop": drop,
	})
}

func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet:
		search := r.URL.Query().Get("search")
		limit := 100

		locked, totalLocked, _ := xdp.ListBlockedIPs(s.manager.LockList(), false, limit, search)
		locked6, totalLocked6, _ := xdp.ListBlockedIPs(s.manager.LockList6(), true, limit, search)
		whitelist, totalWhitelist, _ := xdp.ListBlockedIPs(s.manager.Whitelist(), false, limit, search)
		whitelist6, totalWhitelist6, _ := xdp.ListBlockedIPs(s.manager.Whitelist6(), true, limit, search)

		// Get IP+Port rules (action 1=allow, 2=deny)
		ipPortRules, totalIPPort, _ := s.manager.ListIPPortRules(false, limit, search)
		ipPortRules6, totalIPPort6, _ := s.manager.ListIPPortRules(true, limit, search)

		res := map[string]interface{}{
			"blacklist":     appendMap(locked, locked6),
			"totalBlacklist": totalLocked + totalLocked6,
			"whitelist":     appendMap(whitelist, whitelist6),
			"totalWhitelist": totalWhitelist + totalWhitelist6,
			"ipPortRules":   mergeIPPortMaps(ipPortRules, ipPortRules6),
			"totalIPPort":   totalIPPort + totalIPPort6,
			"limit":         limit,
		}
		json.NewEncoder(w).Encode(res)

	case http.MethodPost:
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
				if isIPv6(req.CIDR) {
					m = s.manager.LockList6()
				} else {
					m = s.manager.LockList()
				}
				err = xdp.LockIP(m, req.CIDR)
			} else if req.Type == "whitelist" {
				// For whitelist, we check if it's an IP+Port rule (e.g. 1.2.3.4:80)
				// Or a standard CIDR (e.g. 1.2.3.4/32)
				port := uint16(0)
				cidr := req.CIDR
				if strings.Contains(cidr, ":") && !strings.Contains(cidr, "[") && !strings.Contains(cidr, "/") && strings.Count(cidr, ":") == 1 {
					// Likely IPv4:Port format
					parts := strings.Split(cidr, ":")
					cidr = parts[0]
					fmt.Sscanf(parts[1], "%d", &port)
				}

				if isIPv6(cidr) {
					m = s.manager.Whitelist6()
				} else {
					m = s.manager.Whitelist()
				}
				err = xdp.AllowIP(m, cidr, port)
			} else if req.Type == "ip_port_rules" {
				// Parse IP:Port and action
				ipStr, port, action, parseErr := parseIPPortAction(req.CIDR)
				if parseErr != nil {
					err = parseErr
				} else {
					if isIPv6(ipStr) {
						m = s.manager.IpPortRules6()
					} else {
						m = s.manager.IpPortRules()
					}

					_, ipNet, err2 := net.ParseCIDR(ipStr)
					if err2 != nil {
						// Try as single IP
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
				if isIPv6(req.CIDR) {
					if req.Type == "blacklist" {
						m = s.manager.LockList6()
					} else {
						m = s.manager.Whitelist6()
					}
				} else {
					if req.Type == "blacklist" {
						m = s.manager.LockList()
					} else {
						m = s.manager.Whitelist()
					}
				}
				err = xdp.UnlockIP(m, req.CIDR)
			}
		}

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Optional: Automatic persistence if enabled in config
		cfg, _ := types.LoadGlobalConfig(s.configPath)
		if cfg != nil && cfg.Base.PersistRules {
			if req.Type == "blacklist" {
				if req.Action == "add" {
					appendToFile(cfg.Base.LockListFile, req.CIDR)
				} else {
					removeFromFile(cfg.Base.LockListFile, req.CIDR)
				}
			} else if req.Type == "whitelist" {
				// Whitelist persistence (update config slice)
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
				// IP+Port rules persistence
				parts := strings.Split(req.CIDR, ":")
				if len(parts) >= 2 {
					ip := parts[0]
					portVal := uint16(0)
					fmt.Sscanf(parts[1], "%d", &portVal)
					actionVal := uint8(2)
					if len(parts) >= 3 && parts[2] == "allow" {
						actionVal = 1
					}

					if req.Action == "add" {
						found := false
						for i, rule := range cfg.Port.IPPortRules {
							if rule.IP == ip && rule.Port == portVal {
								cfg.Port.IPPortRules[i].Action = actionVal
								found = true
								break
							}
						}
						if !found {
							cfg.Port.IPPortRules = append(cfg.Port.IPPortRules, types.IPPortRule{
								IP:     ip,
								Port:   portVal,
								Action: actionVal,
							})
						}
					} else {
						newRules := []types.IPPortRule{}
						for _, rule := range cfg.Port.IPPortRules {
							if rule.IP != ip || rule.Port != portVal {
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
			// Save the updated config back to file (for whitelists)
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

func (s *Server) handleUI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, `
<!DOCTYPE html>
<html>
<head>
    <title>netxfw Dashboard</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background-color: #f8f9fa; }
        .card { margin-bottom: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .stat-value { font-size: 2.5rem; font-weight: bold; }
        .navbar-brand { font-weight: bold; color: #0d6efd !important; }
        code { color: #d63384; }
    </style>
</head>
<body>
    <nav class="navbar navbar-dark bg-dark mb-4">
        <div class="container">
            <a class="navbar-brand" href="#">🛡️ netxfw <small class="text-muted">Management</small></a>
        </div>
    </nav>

    <div class="container">
        <div class="row">
            <div class="col-md-6">
                <div class="card text-center text-white bg-primary">
                    <div class="card-body">
                        <h5 class="card-title">Pass Count</h5>
                        <p class="stat-value" id="pass-count">0</p>
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="card text-center text-white bg-danger">
                    <div class="card-body">
                        <h5 class="card-title">Drop Count</h5>
                        <p class="stat-value" id="drop-count">0</p>
                    </div>
                </div>
            </div>
        </div>

        <div class="row">
            <div class="col-md-12">
                <div class="card">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h5 class="mb-0">Control Center</h5>
                        <div class="d-flex align-items-center">
                            <select id="sync-mode" class="form-select form-select-sm me-2" style="width: auto;">
                                <option value="incremental">Incremental</option>
                                <option value="overwrite">Full Overwrite</option>
                            </select>
                            <button class="btn btn-sm btn-outline-primary me-2" onclick="syncRules('file2map')" title="Load rules from local file to BPF Map">📥 Load from File</button>
                            <button class="btn btn-sm btn-outline-secondary" onclick="syncRules('map2file')" title="Save current BPF Map rules to local file">💾 Sync to File</button>
                        </div>
                    </div>
                    <div class="card-body">
                        <div class="row mb-3">
                            <div class="col-md-12">
                                <div class="input-group">
                                    <span class="input-group-text">🔍 Search Rules</span>
                                    <input type="text" id="rule-search" class="form-control" placeholder="Search IP or CIDR across all tables..." onkeyup="handleSearch(event)">
                                    <button class="btn btn-primary" onclick="refreshRules()">Search</button>
                                </div>
                            </div>
                        </div>
                        <div class="form-check form-switch mb-3">
                            <input class="form-check-input" type="checkbox" id="afxdp-toggle" onchange="toggleConfig('afxdp', this.checked)">
                            <label class="form-check-label" for="afxdp-toggle">Enable AF_XDP Redirection (DPI / AI Path)</label>
                        </div>
                        <div class="form-check form-switch">
                            <input class="form-check-input" type="checkbox" id="deny-toggle" onchange="toggleConfig('default_deny', this.checked)">
                            <label class="form-check-label" for="deny-toggle">Default Deny Policy</label>
                        </div>
                    </div>
                </div>
            </div>
        </div>

                        <div class="row mt-4">
            <div class="col-md-12">
                <div class="card">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h5 class="mb-0">Active Whitelist <small id="whitelist-count" class="text-muted"></small></h5>
                        <button class="btn btn-sm btn-outline-success" onclick="addRulePrompt('whitelist')">+ Add CIDR/Port</button>
                    </div>
                    <div class="card-body p-0">
                        <table class="table table-hover mb-0">
                            <thead>
                                <tr><th>CIDR / Rule</th><th>Port/Info</th><th>Action</th></tr>
                            </thead>
                            <tbody id="whitelist-table"></tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>

        <div class="row">
            <div class="col-md-12">
                <div class="card">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h5 class="mb-0">IP + Port Rules <small id="ipport-count" class="text-muted"></small></h5>
                        <button class="btn btn-sm btn-outline-warning" onclick="addRulePrompt('ip_port_rules')">+ Add IP:Port Rule</button>
                    </div>
                    <div class="card-body p-0">
                        <table class="table table-hover mb-0">
                            <thead>
                                <tr><th>IP / CIDR</th><th>Port</th><th>Policy</th><th>Action</th></tr>
                            </thead>
                            <tbody id="ipport-table"></tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>

        <div class="row">
            <div class="col-md-12">
                <div class="card">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h5 class="mb-0">Active Blacklist <small id="blacklist-count" class="text-muted"></small></h5>
                        <button class="btn btn-sm btn-outline-danger" onclick="addRulePrompt('blacklist')">+ Add CIDR</button>
                    </div>
                    <div class="card-body p-0">
                        <table class="table table-hover mb-0">
                            <thead>
                                <tr><th>CIDR</th><th>Hit Count</th><th>Action</th></tr>
                            </thead>
                            <tbody id="blacklist-table"></tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        function refreshStats() {
            fetch('/api/stats').then(r => r.json()).then(data => {
                document.getElementById('pass-count').innerText = data.pass.toLocaleString();
                document.getElementById('drop-count').innerText = data.drop.toLocaleString();
            });
        }

        function refreshRules() {
            const search = document.getElementById('rule-search').value;
            fetch('/api/rules?search=' + encodeURIComponent(search)).then(r => r.json()).then(data => {
                const limit = data.limit || 100;

                // Update Blacklist
                const btbody = document.getElementById('blacklist-table');
                btbody.innerHTML = '';
                if (data.blacklist) {
                    for (const [cidr, count] of Object.entries(data.blacklist)) {
                        btbody.innerHTML += '<tr>' +
                                '<td><code>' + cidr + '</code></td>' +
                                '<td>' + count + '</td>' +
                                '<td><button class="btn btn-sm btn-danger" onclick="removeRule(\'blacklist\', \'' + cidr + '\')">Unlock</button></td>' +
                            '</tr>';
                    }
                }
                document.getElementById('blacklist-count').innerText =
                    (data.totalBlacklist > limit ? '(Showing ' + limit + ' of ' + data.totalBlacklist + ')' : '(' + data.totalBlacklist + ')');

                // Update Whitelist
                const wtbody = document.getElementById('whitelist-table');
                wtbody.innerHTML = '';
                if (data.whitelist) {
                    for (const [cidr, port] of Object.entries(data.whitelist)) {
                        let info = port > 1 ? "Port: " + port : "Full Access";
                        wtbody.innerHTML += '<tr>' +
                                '<td><code>' + cidr + '</code></td>' +
                                '<td><span class="badge bg-success">' + info + '</span></td>' +
                                '<td><button class="btn btn-sm btn-outline-danger" onclick="removeRule(\'whitelist\', \'' + cidr + '\')">Remove</button></td>' +
                            '</tr>';
                    }
                }
                document.getElementById('whitelist-count').innerText =
                    (data.totalWhitelist > limit ? '(Showing ' + limit + ' of ' + data.totalWhitelist + ')' : '(' + data.totalWhitelist + ')');

                // Update IP+Port Rules
                const ptbody = document.getElementById('ipport-table');
                ptbody.innerHTML = '';
                if (data.ipPortRules) {
                    for (const [key, action] of Object.entries(data.ipPortRules)) {
                        const lastColon = key.lastIndexOf(':');
                        const ip = key.substring(0, lastColon);
                        const port = key.substring(lastColon + 1);
                        const policy = action == 1 ? "ALLOW" : "DENY";
                        const badgeClass = action == 1 ? "bg-success" : "bg-danger";

                        ptbody.innerHTML += '<tr>' +
                                '<td><code>' + ip + '</code></td>' +
                                '<td>' + port + '</td>' +
                                '<td><span class="badge ' + badgeClass + '">' + policy + '</span></td>' +
                                '<td><button class="btn btn-sm btn-outline-danger" onclick="removeRule(\'ip_port_rules\', \'' + key + '\')">Remove</button></td>' +
                            '</tr>';
                    }
                }
                document.getElementById('ipport-count').innerText =
                    (data.totalIPPort > limit ? '(Showing ' + limit + ' of ' + data.totalIPPort + ')' : '(' + data.totalIPPort + ')');
            });
        }

        function handleSearch(event) {
            if (event.key === 'Enter') {
                refreshRules();
            }
        }

        function toggleConfig(key, value) {
            fetch('/api/config', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({key, value})
            });
        }

        function syncRules(direction) {
            const mode = document.getElementById('sync-mode').value;
            let msg = direction === 'map2file' ? 'Confirm sync BPF Map to local file?' :
                      'Confirm ' + mode + ' sync from local file to BPF Map?';
            if (!confirm(msg)) return;

            fetch('/api/sync', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({direction, mode})
            }).then(r => {
                if (r.ok) {
                    alert('Sync successful!');
                    refreshRules();
                } else {
                    r.text().then(txt => alert('Sync failed: ' + txt));
                }
            });
        }

        function addRulePrompt(type) {
            let promptMsg = "Enter IP or CIDR (e.g. 1.2.3.4 or 1.2.3.0/24):";
            if (type === 'ip_port_rules') {
                promptMsg = "Enter Rule as IP:Port:Action (e.g. 1.2.3.4:80:deny or 1.2.3.4:443:allow):";
            }
            const cidr = prompt(promptMsg);
            if (!cidr) return;

            fetch('/api/rules', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({type, action: 'add', cidr})
            }).then(r => {
                if (r.ok) refreshRules();
                else r.text().then(alert);
            });
        }

        function removeRule(type, cidr) {
            if (!confirm('Are you sure you want to remove this rule?')) return;
            fetch('/api/rules', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({type, action: 'remove', cidr})
            }).then(r => {
                if (r.ok) refreshRules();
                else r.text().then(alert);
            });
        }

        // Init
        refreshStats();
        refreshRules();
        setInterval(refreshStats, 3000);
    </script>
</body>
</html>
	`)
}

func appendMap(m1, m2 map[string]uint64) map[string]uint64 {
	if m1 == nil {
		m1 = make(map[string]uint64)
	}
	for k, v := range m2 {
		m1[k] = v
	}
	return m1
}

func mergeIPPortMaps(m1, m2 map[string]string) map[string]string {
	res := make(map[string]string)
	for k, v := range m1 {
		res[k] = v
	}
	for k, v := range m2 {
		res[k] = v
	}
	return res
}

func isIPv6(cidr string) bool {
	// Simple check: if it contains more than one colon, it's likely IPv6
	// If it has one colon, it could be IPv4:Port
	// If it has brackets [::1], it's definitely IPv6
	if strings.Contains(cidr, "[") || strings.Count(cidr, ":") > 1 {
		return true
	}
	return false
}

func appendToFile(filePath, line string) {
	if filePath == "" {
		return
	}
	f, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()

	// Check if already exists
	content, err := os.ReadFile(filePath)
	if err == nil && strings.Contains(string(content), line) {
		return
	}

	f.WriteString(line + "\n")
}

func removeFromFile(filePath, line string) {
	if filePath == "" {
		return
	}
	input, err := os.ReadFile(filePath)
	if err != nil {
		return
	}

	lines := strings.Split(string(input), "\n")
	var newLines []string
	for _, l := range lines {
		trimmed := strings.TrimSpace(l)
		if trimmed != "" && trimmed != line {
			newLines = append(newLines, trimmed)
		}
	}

	os.WriteFile(filePath, []byte(strings.Join(newLines, "\n")+"\n"), 0644)
}

func parseIPPortAction(input string) (string, uint16, uint8, error) {
	// Format: IP:Port:Action or [IP]:Port:Action
	// Action: allow (1) or deny (2)

	// Handle IPv6 with brackets [::1]:80:allow or [::1]:80
	if strings.HasPrefix(input, "[") {
		endBracket := strings.Index(input, "]")
		if endBracket == -1 {
			return "", 0, 0, fmt.Errorf("invalid IPv6 format: missing ]")
		}
		ip := input[1:endBracket]
		rest := input[endBracket+1:]
		if strings.HasPrefix(rest, ":") {
			restParts := strings.Split(strings.TrimPrefix(rest, ":"), ":")
			if len(restParts) < 1 {
				return "", 0, 0, fmt.Errorf("missing port")
			}
			var port uint16
			fmt.Sscanf(restParts[0], "%d", &port)
			action := uint8(2) // Default deny
			if len(restParts) >= 2 {
				if restParts[1] == "allow" {
					action = 1
				} else if restParts[1] == "deny" {
					action = 2
				}
			}
			return ip, port, action, nil
		}
		return "", 0, 0, fmt.Errorf("invalid format after ]")
	}

	// Handle IPv4 or IPv6 without brackets
	parts := strings.Split(input, ":")
	if len(parts) < 2 {
		return "", 0, 0, fmt.Errorf("invalid format, expected IP:Port[:Action]")
	}

	// Check if it's IPv6 without brackets (multiple colons before the port)
	// Example: 2001:db8::1:80:allow
	if strings.Count(input, ":") > 2 {
		last := parts[len(parts)-1]
		if last == "allow" || last == "deny" {
			if len(parts) < 3 {
				return "", 0, 0, fmt.Errorf("invalid IPv6 format without brackets")
			}
			action := uint8(2)
			if last == "allow" {
				action = 1
			}
			var port uint16
			fmt.Sscanf(parts[len(parts)-2], "%d", &port)
			ip := strings.Join(parts[:len(parts)-2], ":")
			return ip, port, action, nil
		} else {
			// No action specified: 2001:db8::1:80
			var port uint16
			fmt.Sscanf(parts[len(parts)-1], "%d", &port)
			ip := strings.Join(parts[:len(parts)-1], ":")
			return ip, port, 2, nil
		}
	}

	// Standard IPv4: 1.2.3.4:80[:allow]
	ip := parts[0]
	var port uint16
	fmt.Sscanf(parts[1], "%d", &port)
	action := uint8(2)
	if len(parts) >= 3 {
		if parts[2] == "allow" {
			action = 1
		}
	}
	return ip, port, action, nil
}
