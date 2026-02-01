package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/internal/xdp"
)

/**
 * syncLockMap interacts with pinned BPF maps to block/unblock ranges.
 */
func syncLockMap(cidrStr string, lock bool) {
	mapPath := "/sys/fs/bpf/netxfw/lock_list"
	if isIPv6(cidrStr) {
		mapPath = "/sys/fs/bpf/netxfw/lock_list6"
	}

	m, err := ebpf.LoadPinnedMap(mapPath, nil)
	if err != nil {
		log.Fatalf("❌ Failed to load pinned map (is the daemon running?): %v", err)
	}
	defer m.Close()

	if lock {
		// Check for conflict in whitelist
		oppositeMapPath := "/sys/fs/bpf/netxfw/whitelist"
		if isIPv6(cidrStr) {
			oppositeMapPath = "/sys/fs/bpf/netxfw/whitelist6"
		}
		if opM, err := ebpf.LoadPinnedMap(oppositeMapPath, nil); err == nil {
			if conflict, msg := xdp.CheckConflict(opM, cidrStr, true); conflict {
				fmt.Printf("⚠️  [Conflict] %s (Already in whitelist).\n", msg)
				if !askConfirmation("Do you want to remove it from whitelist and add to blacklist?") {
					fmt.Println("Aborted.")
					opM.Close()
					return
				}
				// Remove from whitelist
				if err := xdp.UnlockIP(opM, cidrStr); err != nil {
					log.Printf("⚠️  Failed to remove from whitelist: %v", err)
				} else {
					log.Printf("🔓 Removed %s from whitelist", cidrStr)
					// Also update config
					globalCfg, err := types.LoadGlobalConfig("/etc/netxfw/config.yaml")
					if err == nil {
						newWhitelist := []string{}
						for _, ip := range globalCfg.Base.Whitelist {
							if ip != cidrStr && !strings.HasPrefix(ip, cidrStr+":") {
								newWhitelist = append(newWhitelist, ip)
							}
						}
						globalCfg.Base.Whitelist = newWhitelist
						types.SaveGlobalConfig("/etc/netxfw/config.yaml", globalCfg)
					}
				}
			}
			opM.Close()
		}

		if err := xdp.LockIP(m, cidrStr); err != nil {
			log.Fatalf("❌ Failed to lock %s: %v", cidrStr, err)
		}
		log.Printf("🛡️ Locked: %s", cidrStr)

		// Persist to LockListFile if enabled
		globalCfg, err := types.LoadGlobalConfig("/etc/netxfw/config.yaml")
		if err == nil && globalCfg.Base.PersistRules && globalCfg.Base.LockListFile != "" {
			filePath := globalCfg.Base.LockListFile
			// Check if already in file
			found := false
			if f, err := os.Open(filePath); err == nil {
				scanner := bufio.NewScanner(f)
				for scanner.Scan() {
					if strings.TrimSpace(scanner.Text()) == cidrStr {
						found = true
						break
					}
				}
				f.Close()
			}

			if !found {
				f, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
				if err == nil {
					if _, err := f.WriteString(cidrStr + "\n"); err == nil {
						log.Printf("📄 Persisted %s to %s", cidrStr, filePath)
					}
					f.Close()
				}
			}
		}
	} else {
		if err := xdp.UnlockIP(m, cidrStr); err != nil {
			log.Fatalf("❌ Failed to unlock %s: %v", cidrStr, err)
		}
		log.Printf("🔓 Unlocked: %s", cidrStr)

		// Remove from LockListFile if enabled
		globalCfg, err := types.LoadGlobalConfig("/etc/netxfw/config.yaml")
		if err == nil && globalCfg.Base.PersistRules && globalCfg.Base.LockListFile != "" {
			filePath := globalCfg.Base.LockListFile
			if _, err := os.Stat(filePath); err == nil {
				// Read all lines except the one to remove
				input, _ := os.ReadFile(filePath)
				lines := strings.Split(string(input), "\n")
				var newLines []string
				modified := false
				for _, line := range lines {
					trimmed := strings.TrimSpace(line)
					if trimmed != "" && trimmed != cidrStr {
						newLines = append(newLines, trimmed)
					} else if trimmed == cidrStr {
						modified = true
					}
				}
				if modified {
					os.WriteFile(filePath, []byte(strings.Join(newLines, "\n")+"\n"), 0644)
					log.Printf("📄 Removed %s from %s", cidrStr, filePath)
				}
			}
		}
	}
}

/**
 * syncWhitelistMap interacts with pinned BPF maps to allow/unallow ranges.
 */
func syncWhitelistMap(cidrStr string, port uint16, allow bool) {
	mapPath := "/sys/fs/bpf/netxfw/whitelist"
	if isIPv6(cidrStr) {
		mapPath = "/sys/fs/bpf/netxfw/whitelist6"
	}

	m, err := ebpf.LoadPinnedMap(mapPath, nil)
	if err != nil {
		log.Fatalf("❌ Failed to load pinned map (is the daemon running?): %v", err)
	}
	defer m.Close()

	configPath := "/etc/netxfw/config.yaml"
	globalCfg, err := types.LoadGlobalConfig(configPath)

	if allow {
		oppositeMapPath := "/sys/fs/bpf/netxfw/lock_list"
		if isIPv6(cidrStr) {
			oppositeMapPath = "/sys/fs/bpf/netxfw/lock_list6"
		}
		if opM, err := ebpf.LoadPinnedMap(oppositeMapPath, nil); err == nil {
			if conflict, msg := xdp.CheckConflict(opM, cidrStr, false); conflict {
				fmt.Printf("⚠️  [Conflict] %s (Already in blacklist).\n", msg)
				if !askConfirmation("Do you want to remove it from blacklist and add to whitelist?") {
					fmt.Println("Aborted.")
					opM.Close()
					return
				}
				if err := xdp.UnlockIP(opM, cidrStr); err != nil {
					log.Printf("⚠️  Failed to remove from blacklist: %v", err)
				} else {
					log.Printf("🔓 Removed %s from blacklist", cidrStr)
				}
			}
			opM.Close()
		}

		if err := xdp.AllowIP(m, cidrStr, port); err != nil {
			log.Fatalf("❌ Failed to allow %s: %v", cidrStr, err)
		}
		if port > 0 {
			log.Printf("⚪ Whitelisted: %s (port: %d)", cidrStr, port)
		} else {
			log.Printf("⚪ Whitelisted: %s", cidrStr)
		}

		if err == nil {
			entry := cidrStr
			if port > 0 {
				entry = fmt.Sprintf("%s:%d", cidrStr, port)
			}
			found := false
			for _, ip := range globalCfg.Base.Whitelist {
				if ip == entry {
					found = true
					break
				}
			}
			if !found {
				globalCfg.Base.Whitelist = append(globalCfg.Base.Whitelist, entry)
				types.SaveGlobalConfig(configPath, globalCfg)
			}
		}
	} else {
		if err := xdp.UnlockIP(m, cidrStr); err != nil {
			log.Fatalf("❌ Failed to unallow %s: %v", cidrStr, err)
		}
		log.Printf("❌ Removed from whitelist: %s", cidrStr)

		if err == nil {
			newWhitelist := []string{}
			for _, ip := range globalCfg.Base.Whitelist {
				if ip != cidrStr && !strings.HasPrefix(ip, cidrStr+":") {
					newWhitelist = append(newWhitelist, ip)
				}
			}
			globalCfg.Base.Whitelist = newWhitelist
			types.SaveGlobalConfig(configPath, globalCfg)
		}
	}
}

func syncDefaultDeny(enable bool) {
	m, err := xdp.NewManagerFromPins("/sys/fs/bpf/netxfw")
	if err != nil {
		log.Fatalf("❌ Failed to initialize manager from pins: %v", err)
	}
	defer m.Close()

	if err := m.SetDefaultDeny(enable); err != nil {
		log.Fatalf("❌ Failed to set default deny: %v", err)
	}

	configPath := "/etc/netxfw/config.yaml"
	globalCfg, err := types.LoadGlobalConfig(configPath)
	if err == nil {
		globalCfg.Base.DefaultDeny = enable
		types.SaveGlobalConfig(configPath, globalCfg)
	}

	log.Printf("🛡️ Default deny policy set to: %v", enable)
}

func syncEnableAFXDP(enable bool) {
	m, err := xdp.NewManagerFromPins("/sys/fs/bpf/netxfw")
	if err != nil {
		log.Fatalf("❌ Failed to initialize manager from pins: %v", err)
	}
	defer m.Close()

	if err := m.SetEnableAFXDP(enable); err != nil {
		log.Fatalf("❌ Failed to set enable AF_XDP: %v", err)
	}

	configPath := "/etc/netxfw/config.yaml"
	globalCfg, err := types.LoadGlobalConfig(configPath)
	if err == nil {
		globalCfg.Base.EnableAFXDP = enable
		types.SaveGlobalConfig(configPath, globalCfg)
	}

	log.Printf("🚀 AF_XDP redirection set to: %v", enable)
}

func syncAllowedPort(port uint16, allow bool) {
	m, err := xdp.NewManagerFromPins("/sys/fs/bpf/netxfw")
	if err != nil {
		log.Fatalf("❌ Failed to initialize manager from pins: %v", err)
	}
	defer m.Close()

	configPath := "/etc/netxfw/config.yaml"
	globalCfg, err := types.LoadGlobalConfig(configPath)
	if err != nil {
		log.Fatalf("❌ Failed to load global config: %v", err)
	}

	if allow {
		mapFound := false
		ports, _ := m.ListAllowedPorts()
		for _, p := range ports {
			if p == port {
				mapFound = true
				break
			}
		}

		cfgFound := false
		for _, p := range globalCfg.Port.AllowedPorts {
			if p == port {
				cfgFound = true
				break
			}
		}

		if mapFound && cfgFound {
			log.Printf("ℹ️  Port %d is already globally allowed in both BPF and config.", port)
			return
		}

		if !mapFound {
			if err := m.AllowPort(port, nil); err != nil {
				log.Fatalf("❌ Failed to allow port %d: %v", port, err)
			}
		}

		if !cfgFound {
			globalCfg.Port.AllowedPorts = append(globalCfg.Port.AllowedPorts, port)
			types.SaveGlobalConfig(configPath, globalCfg)
			log.Printf("📄 Added port %d to config", port)
		}

		if !mapFound || !cfgFound {
			log.Printf("🔓 Port allowed globally: %d (Updated BPF: %v, Updated Config: %v)", port, !mapFound, !cfgFound)
		}
	} else {
		if err := m.RemovePort(port); err != nil {
			log.Fatalf("❌ Failed to disallow port %d: %v", port, err)
		}
		newPorts := []uint16{}
		for _, p := range globalCfg.Port.AllowedPorts {
			if p != port {
				newPorts = append(newPorts, p)
			}
		}
		globalCfg.Port.AllowedPorts = newPorts
		types.SaveGlobalConfig(configPath, globalCfg)
		log.Printf("🔒 Port removed from global allow list: %d", port)
	}
}

func syncIPPortRule(cidrStr string, port uint16, action uint8, add bool) {
	m, err := xdp.NewManagerFromPins("/sys/fs/bpf/netxfw")
	if err != nil {
		log.Fatalf("❌ Failed to initialize manager from pins: %v", err)
	}
	defer m.Close()

	configPath := "/etc/netxfw/config.yaml"
	globalCfg, _ := types.LoadGlobalConfig(configPath)
	if globalCfg == nil {
		globalCfg = &types.GlobalConfig{}
	}

	_, ipNet, err := net.ParseCIDR(cidrStr)
	if err != nil {
		ip := net.ParseIP(cidrStr)
		if ip == nil {
			log.Fatalf("❌ Invalid IP address: %s", cidrStr)
		}
		mask := net.CIDRMask(32, 32)
		if ip.To4() == nil {
			mask = net.CIDRMask(128, 128)
		}
		ipNet = &net.IPNet{IP: ip, Mask: mask}
	}

	if add {
		isV6 := ipNet.IP.To4() == nil
		existingRules, _, _ := m.ListIPPortRules(isV6, 0, "")
		targetKey := fmt.Sprintf("%s:%d", cidrStr, port)
		if !strings.Contains(cidrStr, "/") {
			if isV6 {
				targetKey = fmt.Sprintf("%s/128:%d", ipNet.IP.String(), port)
			} else {
				targetKey = fmt.Sprintf("%s/32:%d", ipNet.IP.String(), port)
			}
		}

		mapAction := uint8(0)
		for k, v := range existingRules {
			if k == targetKey {
				if v == "allow" {
					mapAction = 1
				} else {
					mapAction = 2
				}
				break
			}
		}

		cfgAction := uint8(0)
		cfgIdx := -1
		for i, r := range globalCfg.Port.IPPortRules {
			if r.IP == cidrStr && r.Port == port {
				cfgAction = r.Action
				cfgIdx = i
				break
			}
		}

		if mapAction == action && cfgAction == action {
			actionStr := "allow"
			if action == 2 {
				actionStr = "deny"
			}
			fmt.Printf("ℹ️  Rule already exists: %s:%d -> %s\n", cidrStr, port, actionStr)
			return
		}

		if action == 1 { // Allow
			oppositeMapPath := "/sys/fs/bpf/netxfw/lock_list"
			if isIPv6(cidrStr) {
				oppositeMapPath = "/sys/fs/bpf/netxfw/lock_list6"
			}
			if opM, err := ebpf.LoadPinnedMap(oppositeMapPath, nil); err == nil {
				if conflict, msg := xdp.CheckConflict(opM, cidrStr, false); conflict {
					fmt.Printf("⚠️  [Conflict] %s (Already in blacklist).\n", msg)
					if !askConfirmation("Do you want to remove it from blacklist and add this allow rule?") {
						fmt.Println("Aborted.")
						opM.Close()
						return
					}
					xdp.UnlockIP(opM, cidrStr)
				}
				opM.Close()
			}
		} else if action == 2 { // Deny
			oppositeMapPath := "/sys/fs/bpf/netxfw/whitelist"
			if isIPv6(cidrStr) {
				oppositeMapPath = "/sys/fs/bpf/netxfw/whitelist6"
			}
			if opM, err := ebpf.LoadPinnedMap(oppositeMapPath, nil); err == nil {
				if conflict, msg := xdp.CheckConflict(opM, cidrStr, true); conflict {
					fmt.Printf("⚠️  [Conflict] %s (Already in whitelist).\n", msg)
					if !askConfirmation("Do you want to remove it from whitelist and add this deny rule?") {
						fmt.Println("Aborted.")
						opM.Close()
						return
					}
					xdp.UnlockIP(opM, cidrStr)
				}
				opM.Close()
			}
		}

		if mapAction != action {
			if err := m.AddIPPortRule(ipNet, port, action, nil); err != nil {
				log.Fatalf("❌ Failed to add IP+Port rule: %v", err)
			}
		}

		if cfgAction != action {
			persist := true
			if action == 2 && !globalCfg.Base.PersistRules {
				persist = false
			}
			if persist {
				if cfgIdx >= 0 {
					globalCfg.Port.IPPortRules[cfgIdx].Action = action
				} else {
					globalCfg.Port.IPPortRules = append(globalCfg.Port.IPPortRules, types.IPPortRule{
						IP:     cidrStr,
						Port:   port,
						Action: action,
					})
				}
				types.SaveGlobalConfig(configPath, globalCfg)
				log.Printf("📄 Updated IP+Port rule in config: %s:%d", cidrStr, port)
			}
		}

		if mapAction != action || cfgAction != action {
			actionStr := "allow"
			if action == 2 {
				actionStr = "deny"
			}
			log.Printf("🛡️ Rule added: %s:%d -> %s (Updated BPF: %v, Updated Config: %v)",
				cidrStr, port, actionStr, mapAction != action, cfgAction != action)
		}
	} else {
		if err := m.RemoveIPPortRule(ipNet, port); err != nil {
			log.Fatalf("❌ Failed to remove IP+Port rule: %v", err)
		}
		foundInConfig := false
		isDenyRule := false
		for _, r := range globalCfg.Port.IPPortRules {
			if r.IP == cidrStr && r.Port == port {
				foundInConfig = true
				if r.Action == 2 {
					isDenyRule = true
				}
				break
			}
		}
		if foundInConfig {
			persist := true
			if isDenyRule && !globalCfg.Base.PersistRules {
				persist = false
			}
			if persist {
				newRules := []types.IPPortRule{}
				for _, r := range globalCfg.Port.IPPortRules {
					if r.IP != cidrStr || r.Port != port {
						newRules = append(newRules, r)
					}
				}
				globalCfg.Port.IPPortRules = newRules
				types.SaveGlobalConfig(configPath, globalCfg)
				log.Printf("🛡️ Rule removed from config: %s:%d", cidrStr, port)
			}
		}
		log.Printf("🛡️ Rule removed from BPF: %s:%d", cidrStr, port)
	}
}

func clearBlacklist() {
	if !askConfirmation("⚠️  Are you sure you want to clear the ENTIRE blacklist (IPs and IP+Port deny rules)?") {
		fmt.Println("Aborted.")
		return
	}

	m4, err := ebpf.LoadPinnedMap("/sys/fs/bpf/netxfw/lock_list", nil)
	if err == nil {
		removed, _ := xdp.ClearMap(m4)
		log.Printf("🧹 Cleared %d entries from IPv4 lock list", removed)
		m4.Close()
	}

	m6, err := ebpf.LoadPinnedMap("/sys/fs/bpf/netxfw/lock_list6", nil)
	if err == nil {
		removed, _ := xdp.ClearMap(m6)
		log.Printf("🧹 Cleared %d entries from IPv6 lock list", removed)
		m6.Close()
	}

	mgr, err := xdp.NewManagerFromPins("/sys/fs/bpf/netxfw")
	if err == nil {
		clearDenyRules := func(mapPtr *ebpf.Map) int {
			removed := 0
			iter := mapPtr.Iterate()
			var k interface{}
			var v xdp.NetXfwRuleValue
			for iter.Next(&k, &v) {
				if v.Counter == 2 { // Action Deny
					if err := mapPtr.Delete(k); err == nil {
						removed++
					}
				}
			}
			return removed
		}
		removedP4 := clearDenyRules(mgr.IpPortRules())
		removedP6 := clearDenyRules(mgr.IpPortRules6())
		if removedP4+removedP6 > 0 {
			log.Printf("🧹 Cleared %d IP+Port deny rules from BPF", removedP4+removedP6)
		}
		mgr.Close()
	}

	configPath := "/etc/netxfw/config.yaml"
	globalCfg, err := types.LoadGlobalConfig(configPath)
	if err == nil {
		if globalCfg.Base.LockListFile != "" {
			os.WriteFile(globalCfg.Base.LockListFile, []byte(""), 0644)
			log.Printf("📄 Cleared blacklist file: %s", globalCfg.Base.LockListFile)
		}
		var newRules []types.IPPortRule
		removedCount := 0
		for _, r := range globalCfg.Port.IPPortRules {
			if r.Action != 2 {
				newRules = append(newRules, r)
			} else {
				removedCount++
			}
		}
		if removedCount > 0 {
			globalCfg.Port.IPPortRules = newRules
			types.SaveGlobalConfig(configPath, globalCfg)
			log.Printf("📄 Removed %d deny rules from config.yaml", removedCount)
		}
	}
	log.Println("✅ Blacklist cleared successfully.")
}

func importIPPortRulesFromFile(filePath string) {
	file, err := os.Open(filePath)
	if err != nil {
		log.Fatalf("❌ Failed to open rules file: %v", err)
	}
	defer file.Close()

	m, err := xdp.NewManagerFromPins("/sys/fs/bpf/netxfw")
	if err != nil {
		log.Fatalf("❌ Failed to initialize manager from pins: %v", err)
	}
	defer m.Close()

	configPath := "/etc/netxfw/config.yaml"
	globalCfg, _ := types.LoadGlobalConfig(configPath)
	if globalCfg == nil {
		globalCfg = &types.GlobalConfig{}
	}

	existingRules4, _, _ := m.ListIPPortRules(false, 0, "")
	existingRules6, _, _ := m.ListIPPortRules(true, 0, "")

	scanner := bufio.NewScanner(file)
	count := 0
	updatedCount := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}

		cidrStr := parts[0]
		pVal, _ := strconv.ParseUint(parts[1], 10, 16)
		port := uint16(pVal)
		aVal, _ := strconv.ParseUint(parts[2], 10, 8)
		action := uint8(aVal)

		_, ipNet, err := net.ParseCIDR(cidrStr)
		if err != nil {
			ip := net.ParseIP(cidrStr)
			if ip == nil {
				continue
			}
			mask := net.CIDRMask(32, 32)
			if ip.To4() == nil {
				mask = net.CIDRMask(128, 128)
			}
			ipNet = &net.IPNet{IP: ip, Mask: mask}
		}

		isV6 := ipNet.IP.To4() == nil
		targetKey := ""
		if !strings.Contains(cidrStr, "/") {
			if isV6 {
				targetKey = fmt.Sprintf("%s/128:%d", ipNet.IP.String(), port)
			} else {
				targetKey = fmt.Sprintf("%s/32:%d", ipNet.IP.String(), port)
			}
		} else {
			targetKey = fmt.Sprintf("%s:%d", cidrStr, port)
		}

		mapAction := uint8(0)
		existingMap := existingRules4
		if isV6 {
			existingMap = existingRules6
		}
		if v, ok := existingMap[targetKey]; ok {
			if v == "allow" {
				mapAction = 1
			} else {
				mapAction = 2
			}
		}

		if mapAction != action {
			if err := m.AddIPPortRule(ipNet, port, action, nil); err == nil {
				updatedCount++
			}
		}

		found := false
		for i, r := range globalCfg.Port.IPPortRules {
			if r.IP == cidrStr && r.Port == port {
				if globalCfg.Port.IPPortRules[i].Action != action {
					globalCfg.Port.IPPortRules[i].Action = action
					updatedCount++
				}
				found = true
				break
			}
		}
		if !found {
			globalCfg.Port.IPPortRules = append(globalCfg.Port.IPPortRules, types.IPPortRule{
				IP:     cidrStr,
				Port:   port,
				Action: action,
			})
			updatedCount++
		}
		count++
	}

	if updatedCount > 0 {
		types.SaveGlobalConfig(configPath, globalCfg)
	}
	log.Printf("🚀 Successfully processed %d IP+Port rules (New/Updated: %d).", count, updatedCount)
}

func importLockListFromFile(filePath string) {
	m4, err := ebpf.LoadPinnedMap("/sys/fs/bpf/netxfw/lock_list", nil)
	if err != nil {
		log.Fatalf("❌ Failed to load IPv4 lock list (is the daemon running?): %v", err)
	}
	defer m4.Close()

	m6, err := ebpf.LoadPinnedMap("/sys/fs/bpf/netxfw/lock_list6", nil)
	if err != nil {
		log.Fatalf("❌ Failed to load IPv6 lock list (is the daemon running?): %v", err)
	}
	defer m6.Close()

	file, err := os.Open(filePath)
	if err != nil {
		log.Fatalf("❌ Failed to open lock list file %s: %v", filePath, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	count := 0
	conflictCount := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		var targetMap *ebpf.Map
		var oppositeMap *ebpf.Map
		if !isIPv6(line) {
			targetMap = m4
			oppositeMap, _ = ebpf.LoadPinnedMap("/sys/fs/bpf/netxfw/whitelist", nil)
		} else {
			targetMap = m6
			oppositeMap, _ = ebpf.LoadPinnedMap("/sys/fs/bpf/netxfw/whitelist6", nil)
		}

		if oppositeMap != nil {
			if conflict, _ := xdp.CheckConflict(oppositeMap, line, true); conflict {
				conflictCount++
				oppositeMap.Close()
				continue
			}
			oppositeMap.Close()
		}

		if err := xdp.LockIP(targetMap, line); err == nil {
			count++
		}
	}
	log.Printf("🛡️ Imported %d IPs/ranges from %s to lock list (Skipped %d conflicts)", count, filePath, conflictCount)
}

func importWhitelistFromFile(filePath string) {
	m4, err := ebpf.LoadPinnedMap("/sys/fs/bpf/netxfw/whitelist", nil)
	if err != nil {
		log.Fatalf("❌ Failed to load IPv4 whitelist (is the daemon running?): %v", err)
	}
	defer m4.Close()

	m6, err := ebpf.LoadPinnedMap("/sys/fs/bpf/netxfw/whitelist6", nil)
	if err != nil {
		log.Fatalf("❌ Failed to load IPv6 whitelist (is the daemon running?): %v", err)
	}
	defer m6.Close()

	file, err := os.Open(filePath)
	if err != nil {
		log.Fatalf("❌ Failed to open whitelist file %s: %v", filePath, err)
	}
	defer file.Close()

	configPath := "/etc/netxfw/config.yaml"
	globalCfg, _ := types.LoadGlobalConfig(configPath)
	if globalCfg == nil {
		globalCfg = &types.GlobalConfig{}
	}

	scanner := bufio.NewScanner(file)
	count := 0
	conflictCount := 0
	updatedConfig := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		cidr := line
		var port uint16
		if strings.HasPrefix(line, "[") && strings.Contains(line, "]:") {
			endBracket := strings.LastIndex(line, "]")
			portStr := line[endBracket+2:]
			cidr = line[1:endBracket]
			fmt.Sscanf(portStr, "%d", &port)
		} else if strings.Contains(line, "/") {
			lastColon := strings.LastIndex(line, ":")
			if lastColon > strings.LastIndex(line, "/") {
				portStr := line[lastColon+1:]
				cidr = line[:lastColon]
				fmt.Sscanf(portStr, "%d", &port)
			}
		} else if !isIPv6(line) && strings.Contains(line, ":") {
			parts := strings.Split(line, ":")
			if len(parts) == 2 {
				cidr = parts[0]
				fmt.Sscanf(parts[1], "%d", &port)
			}
		}

		var targetMap *ebpf.Map
		var oppositeMap *ebpf.Map
		if !isIPv6(cidr) {
			targetMap = m4
			oppositeMap, _ = ebpf.LoadPinnedMap("/sys/fs/bpf/netxfw/lock_list", nil)
		} else {
			targetMap = m6
			oppositeMap, _ = ebpf.LoadPinnedMap("/sys/fs/bpf/netxfw/lock_list6", nil)
		}

		if oppositeMap != nil {
			if conflict, _ := xdp.CheckConflict(oppositeMap, cidr, false); conflict {
				conflictCount++
				oppositeMap.Close()
				continue
			}
			oppositeMap.Close()
		}

		if err := xdp.AllowIP(targetMap, cidr, port); err == nil {
			count++
			found := false
			for _, ip := range globalCfg.Base.Whitelist {
				if ip == line {
					found = true
					break
				}
			}
			if !found {
				globalCfg.Base.Whitelist = append(globalCfg.Base.Whitelist, line)
				updatedConfig = true
			}
		}
	}

	if updatedConfig {
		types.SaveGlobalConfig(configPath, globalCfg)
	}
	log.Printf("⚪ Imported %d IPs/ranges from %s to whitelist (Skipped %d conflicts, Updated config: %v)", count, filePath, conflictCount, updatedConfig)
}
