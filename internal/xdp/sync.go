package xdp

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/livp123/netxfw/internal/binary"
	"github.com/livp123/netxfw/internal/plugins/types"
)

// SyncFromFiles reads rules from text files and updates BPF maps.
// If overwrite is true, it clears existing rules in the maps first.
func (m *Manager) SyncFromFiles(cfg *types.GlobalConfig, overwrite bool) error {
	if cfg.Base.LockListFile == "" || cfg.Base.LockListBinary == "" {
		return fmt.Errorf("lock_list_file and lock_list_binary must be configured for sync")
	}

	if overwrite {
		log.Printf("🧹 Overwrite mode: Clearing BPF maps before sync...")
		m.ClearMaps()
	}

	log.Printf("🔄 Syncing rules from %s and config to BPF maps...", cfg.Base.LockListFile)

	// 1. Sync Whitelist from config to maps
	for _, rule := range cfg.Base.Whitelist {
		cidr := rule
		port := uint16(0)
		if strings.Contains(rule, ":") && !strings.Contains(rule, "[") && !strings.Contains(rule, "/") {
			parts := strings.Split(rule, ":")
			if len(parts) == 2 {
				cidr = parts[0]
				fmt.Sscanf(parts[1], "%d", &port)
			}
		}

		var targetMap *ebpf.Map
		if strings.Contains(cidr, ":") {
			targetMap = m.whitelist6
		} else {
			targetMap = m.whitelist
		}

		if targetMap != nil {
			if err := AllowIP(targetMap, cidr, port); err != nil {
				log.Printf("⚠️  Failed to whitelist %s: %v", rule, err)
			}
		}
	}

	// 2. Read and parse rules.deny.txt
	file, err := os.Open(cfg.Base.LockListFile)
	if err != nil {
		return fmt.Errorf("failed to open lock list file: %w", err)
	}
	defer file.Close()

	var records []binary.Record
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		ip, ipNet, err := net.ParseCIDR(line)
		var ones int
		if err != nil {
			ip = net.ParseIP(line)
			if ip == nil {
				log.Printf("⚠️  Skipping invalid IP/CIDR: %s", line)
				continue
			}
			if ip.To4() != nil {
				ones = 32
			} else {
				ones = 128
			}
		} else {
			ones, _ = ipNet.Mask.Size()
		}

		records = append(records, binary.Record{
			IP:        ip,
			PrefixLen: uint8(ones),
			IsIPv6:    ip.To4() == nil,
		})
	}

	// 2. Update BPF Maps
	for _, r := range records {
		var targetMap *ebpf.Map
		if r.IsIPv6 {
			targetMap = m.lockList6
		} else {
			targetMap = m.lockList
		}

		if targetMap == nil {
			continue
		}

		if err := LockIP(targetMap, fmt.Sprintf("%s/%d", r.IP.String(), r.PrefixLen)); err != nil {
			log.Printf("⚠️  Failed to lock %s/%d: %v", r.IP.String(), r.PrefixLen, err)
		}
	}

	// 3. Sync IP+Port rules from config to maps
	for _, rule := range cfg.Port.IPPortRules {
		_, ipNet, err := net.ParseCIDR(rule.IP)
		if err != nil {
			ip := net.ParseIP(rule.IP)
			if ip != nil {
				mask := net.CIDRMask(32, 32)
				if ip.To4() == nil {
					mask = net.CIDRMask(128, 128)
				}
				ipNet = &net.IPNet{IP: ip, Mask: mask}
			}
		}
		if ipNet != nil {
			if err := m.AddIPPortRule(ipNet, rule.Port, rule.Action, nil); err != nil {
				log.Printf("⚠️  Failed to add IP+Port rule %s:%d (action %d): %v", rule.IP, rule.Port, rule.Action, err)
			}
		}
	}

	// 4. Sync allowed ports from config to maps
	for _, port := range cfg.Port.AllowedPorts {
		if err := m.AllowPort(port, nil); err != nil {
			log.Printf("⚠️  Failed to allow port %d: %v", port, err)
		}
	}

	// 5. Sync rate limit rules from config to maps
	for _, rule := range cfg.RateLimit.Rules {
		_, ipNet, err := net.ParseCIDR(rule.IP)
		if err != nil {
			ip := net.ParseIP(rule.IP)
			if ip != nil {
				mask := net.CIDRMask(32, 32)
				if ip.To4() == nil {
					mask = net.CIDRMask(128, 128)
				}
				ipNet = &net.IPNet{IP: ip, Mask: mask}
			}
		}
		if ipNet != nil {
			if err := m.AddRateLimitRule(ipNet, rule.Rate, rule.Burst); err != nil {
				log.Printf("⚠️  Failed to add rate limit rule %s: %v", rule.IP, err)
			}
		}
	}

	// 6. Sync Global Config from config to maps
	m.SetDefaultDeny(cfg.Base.DefaultDeny)
	m.SetAllowReturnTraffic(cfg.Base.AllowReturnTraffic)
	m.SetAllowICMP(cfg.Base.AllowICMP)
	m.SetEnableAFXDP(cfg.Base.EnableAFXDP)
	m.SetICMPRateLimit(cfg.Base.ICMPRate, cfg.Base.ICMPBurst)
	m.SetEnableRateLimit(cfg.RateLimit.Enabled)
	m.SetConntrack(cfg.Conntrack.Enabled)
	if cfg.Conntrack.TCPTimeout != "" {
		if d, err := time.ParseDuration(cfg.Conntrack.TCPTimeout); err == nil {
			m.SetConntrackTimeout(d)
		}
	}

	// 7. (Optional) Update binary cache for fast loading on restart
	go m.UpdateBinaryCache(cfg, records)

	return nil
}

// UpdateBinaryCache encodes records to binary format and compresses them.
func (m *Manager) UpdateBinaryCache(cfg *types.GlobalConfig, records []binary.Record) {
	if cfg.Base.LockListBinary == "" {
		return
	}

	tmpBin := cfg.Base.LockListBinary + ".tmp"
	tmpFile, err := os.Create(tmpBin)
	if err != nil {
		log.Printf("❌ Failed to create temporary binary file: %v", err)
		return
	}

	if err := binary.Encode(tmpFile, records); err != nil {
		tmpFile.Close()
		os.Remove(tmpBin)
		log.Printf("❌ Failed to encode binary records: %v", err)
		return
	}
	tmpFile.Close()

	cmd := exec.Command("zstd", "-f", "-o", cfg.Base.LockListBinary, tmpBin)
	if output, err := cmd.CombinedOutput(); err != nil {
		os.Remove(tmpBin)
		log.Printf("❌ Failed to compress with zstd: %v\nOutput: %s", err, string(output))
		return
	}
	os.Remove(tmpBin)
	log.Printf("✅ Successfully updated binary cache %s", cfg.Base.LockListBinary)
}

// SyncToFiles dumps current BPF map rules back to text files.
func (m *Manager) SyncToFiles(cfg *types.GlobalConfig) error {
	if cfg.Base.LockListFile == "" {
		return fmt.Errorf("lock_list_file must be configured")
	}

	log.Printf("💾 Syncing BPF maps to %s and config object...", cfg.Base.LockListFile)

	// 1. Sync Whitelist from maps to config object
	wl, _, err := ListBlockedIPs(m.whitelist, false, 0, "")
	if err == nil {
		wl6, _, err := ListBlockedIPs(m.whitelist6, true, 0, "")
		if err == nil {
			newWhitelist := []string{}
			for cidr, port := range wl {
				if port > 1 {
					newWhitelist = append(newWhitelist, fmt.Sprintf("%s:%d", cidr, port))
				} else {
					newWhitelist = append(newWhitelist, cidr)
				}
			}
			for cidr, port := range wl6 {
				if port > 1 {
					newWhitelist = append(newWhitelist, fmt.Sprintf("[%s]:%d", cidr, port))
				} else {
					newWhitelist = append(newWhitelist, cidr)
				}
			}
			cfg.Base.Whitelist = newWhitelist
		}
	}

	// 2. List all blocked IPs
	ips, _, err := ListBlockedIPs(m.lockList, false, 0, "")
	if err != nil {
		return err
	}
	ips6, _, err := ListBlockedIPs(m.lockList6, true, 0, "")
	if err != nil {
		return err
	}

	// 3. Sync IP+Port rules from maps to config object
	ipPortRules, _, err := m.ListIPPortRules(false, 0, "")
	if err == nil {
		ipPortRules6, _, err := m.ListIPPortRules(true, 0, "")
		if err == nil {
			var newIPPortRules []types.IPPortRule

			// Helper to parse the map back to struct
			processRules := func(rules map[string]string) {
				for key, actionStr := range rules {
					// Key is "IP/PrefixLen:Port"
					lastColon := strings.LastIndex(key, ":")
					if lastColon != -1 {
						ipCIDR := key[:lastColon]
						portStr := key[lastColon+1:]
						port := uint16(0)
						fmt.Sscanf(portStr, "%d", &port)

						action := uint8(2) // deny
						if actionStr == "allow" {
							action = 1
						}

						newIPPortRules = append(newIPPortRules, types.IPPortRule{
							IP:     ipCIDR,
							Port:   port,
							Action: action,
						})
					}
				}
			}

			processRules(ipPortRules)
			processRules(ipPortRules6)
			cfg.Port.IPPortRules = newIPPortRules
		}
	}

	// 4. Sync allowed ports from map to config object
	if ports, err := m.ListAllowedPorts(); err == nil {
		cfg.Port.AllowedPorts = ports
	}

	// 5. Sync rate limit rules from map to config object
	if rules, _, err := m.ListRateLimitRules(0, ""); err == nil {
		var newRateRules []types.RateLimitRule
		for target, conf := range rules {
			newRateRules = append(newRateRules, types.RateLimitRule{
				IP:    target,
				Rate:  conf.Rate,
				Burst: conf.Burst,
			})
		}
		cfg.RateLimit.Rules = newRateRules
	}

	// 6. Sync Global Config from map to config object
	if m.globalConfig != nil {
		var val uint64
		var key uint32

		key = configDefaultDeny
		if err := m.globalConfig.Lookup(&key, &val); err == nil {
			cfg.Base.DefaultDeny = (val == 1)
		}
		key = configAllowReturnTraffic
		if err := m.globalConfig.Lookup(&key, &val); err == nil {
			cfg.Base.AllowReturnTraffic = (val == 1)
		}
		key = configAllowICMP
		if err := m.globalConfig.Lookup(&key, &val); err == nil {
			cfg.Base.AllowICMP = (val == 1)
		}
		key = configEnableAFXDP
		if err := m.globalConfig.Lookup(&key, &val); err == nil {
			cfg.Base.EnableAFXDP = (val == 1)
		}
		key = configICMPRate
		if err := m.globalConfig.Lookup(&key, &val); err == nil {
			cfg.Base.ICMPRate = val
		}
		key = configICMPBurst
		if err := m.globalConfig.Lookup(&key, &val); err == nil {
			cfg.Base.ICMPBurst = val
		}
		key = configEnableRateLimit
		if err := m.globalConfig.Lookup(&key, &val); err == nil {
			cfg.RateLimit.Enabled = (val == 1)
		}
		key = configEnableConntrack
		if err := m.globalConfig.Lookup(&key, &val); err == nil {
			cfg.Conntrack.Enabled = (val == 1)
		}
		key = configConntrackTimeout
		if err := m.globalConfig.Lookup(&key, &val); err == nil {
			cfg.Conntrack.TCPTimeout = time.Duration(val).String()
		}
	}

	file, err := os.Create(cfg.Base.LockListFile)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	writer.WriteString("# netxfw rules - exported at " + time.Now().Format(time.RFC3339) + "\n")

	for cidr := range ips {
		writer.WriteString(cidr + "\n")
	}
	for cidr := range ips6 {
		writer.WriteString(cidr + "\n")
	}

	return writer.Flush()
}

// ClearMaps clears all rules from blacklist and whitelist maps.
func (m *Manager) ClearMaps() {
	maps := []*ebpf.Map{m.lockList, m.lockList6, m.whitelist, m.whitelist6, m.ipPortRules, m.ipPortRules6}
	for _, emap := range maps {
		if emap == nil {
			continue
		}
		var key []byte
		iter := emap.Iterate()
		for iter.Next(&key, nil) {
			emap.Delete(key)
		}
	}
	log.Printf("✅ All BPF maps cleared.")
}
