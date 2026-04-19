package api

import (
	"encoding/json"
	"net/http"
	"sync"

	"github.com/netxfw/netxfw/internal/utils/iputil"
	sdk "github.com/netxfw/netxfw/pkg/sdk"
)

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

		var locked = make([]sdk.BlockedIP, 0)
		var totalLocked int
		var whitelist = make([]string, 0)
		var totalWhitelist int
		var ipPortRules = make([]sdk.IPPortRule, 0)
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
			Type   string `json:"type"`
			Action string `json:"action"`
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
