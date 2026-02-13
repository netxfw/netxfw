package core

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
	"github.com/livp123/netxfw/internal/utils/ipmerge"
	"github.com/livp123/netxfw/internal/xdp"
)

// SyncIPPortRule updates the ip_port_rules map and config.
// action: 1 = Allow, 2 = Deny (mapped from CLI)
// SyncIPPortRule 更新 ip_port_rules Map 和配置。
// action: 1 = 允许, 2 = 拒绝 (从 CLI 映射)
func SyncIPPortRule(ip string, port uint16, action uint8, add bool) {
	mapPath := "/sys/fs/bpf/netxfw/ip_port_rules"

	m, err := ebpf.LoadPinnedMap(mapPath, nil)
	if err != nil {
		log.Fatalf("❌ Failed to load pinned map (is the daemon running?): %v", err)
	}
	defer m.Close()

	cidr := ensureCIDR(ip)

	if add {
		if err := xdp.AddIPPortRule(m, cidr, port, action); err != nil {
			log.Fatalf("❌ Failed to add rule %s:%d: %v", cidr, port, err)
		}
		log.Printf("🛡️ Added IP+Port rule: %s:%d -> Action %d", cidr, port, action)
	} else {
		if err := xdp.RemoveIPPortRule(m, cidr, port); err != nil {
			log.Printf("⚠️  Failed to remove rule %s:%d: %v", cidr, port, err)
		} else {
			log.Printf("🛡️ Removed IP+Port rule: %s:%d", cidr, port)
		}
	}

	// Update Config / 更新配置
	configPath := "/etc/netxfw/config.yaml"
	globalCfg, err := types.LoadGlobalConfig(configPath)
	if err == nil {
		newRules := []types.IPPortRule{}
		modified := false
		targetCIDR := ensureCIDR(ip)

		for _, r := range globalCfg.Port.IPPortRules {
			// Normalize existing rule IP / 标准化现有规则 IP
			ruleCIDR := ensureCIDR(r.IP)
			if ruleCIDR == targetCIDR && r.Port == port {
				if add {
					// Update existing if action changed / 如果动作改变，则更新现有规则
					if r.Action != action {
						r.Action = action
						modified = true
					}
					newRules = append(newRules, r) // Keep it (updated or same) / 保留它（已更新或未变）
				} else {
					modified = true // Remove it (skip append) / 移除它（跳过追加）
				}
			} else {
				newRules = append(newRules, r)
			}
		}

		if add && !modified {
			// Check if we found it in the loop / 检查是否在循环中找到了它
			found := false
			for i, r := range newRules {
				if ensureCIDR(r.IP) == targetCIDR && r.Port == port {
					found = true
					if r.Action != action {
						newRules[i].Action = action
						modified = true
					}
					break
				}
			}
			if !found {
				newRules = append(newRules, types.IPPortRule{
					IP:     ip,
					Port:   port,
					Action: action,
				})
				modified = true
			}
		}

		if modified {
			globalCfg.Port.IPPortRules = newRules
			OptimizeIPPortRulesConfig(globalCfg)
			types.SaveGlobalConfig(configPath, globalCfg)
		}
	}
}

// SyncAllowedPort updates the allowed_ports map and config.
// SyncAllowedPort 更新 allowed_ports Map 和配置。
func SyncAllowedPort(port uint16, add bool) {
	m, err := ebpf.LoadPinnedMap("/sys/fs/bpf/netxfw/allowed_ports", nil)
	if err != nil {
		log.Fatalf("❌ Failed to load pinned map: %v", err)
	}
	defer m.Close()

	if add {
		if err := xdp.AllowPort(m, port); err != nil {
			log.Fatalf("❌ Failed to allow port %d: %v", port, err)
		}
		log.Printf("🔓 Allowed global port: %d", port)
	} else {
		if err := xdp.RemoveAllowedPort(m, port); err != nil {
			log.Printf("⚠️  Failed to remove allowed port %d: %v", port, err)
		} else {
			log.Printf("🔒 Removed allowed global port: %d", port)
		}
	}

	// Update Config / 更新配置
	configPath := "/etc/netxfw/config.yaml"
	globalCfg, err := types.LoadGlobalConfig(configPath)
	if err == nil {
		newPorts := []uint16{}
		modified := false
		found := false
		for _, p := range globalCfg.Port.AllowedPorts {
			if p == port {
				found = true
				if !add {
					modified = true // Remove / 移除
					continue
				}
			}
			newPorts = append(newPorts, p)
		}

		if add && !found {
			newPorts = append(newPorts, port)
			modified = true
		}

		if modified {
			globalCfg.Port.AllowedPorts = newPorts
			types.SaveGlobalConfig(configPath, globalCfg)
		}
	}
}

// SyncRateLimitRule updates the rate_limit_rules map and config.
// SyncRateLimitRule 更新 rate_limit_rules Map 和配置。
func SyncRateLimitRule(ip string, rate uint64, burst uint64, add bool) {
	mapPath := "/sys/fs/bpf/netxfw/ratelimit_config"

	m, err := ebpf.LoadPinnedMap(mapPath, nil)
	if err != nil {
		log.Fatalf("❌ Failed to load pinned map: %v", err)
	}
	defer m.Close()

	cidr := ensureCIDR(ip)

	if add {
		if err := xdp.AddRateLimitRule(m, cidr, rate, burst); err != nil {
			log.Fatalf("❌ Failed to add rate limit rule %s: %v", cidr, err)
		}
		log.Printf("🚀 Added rate limit: %s -> %d pps (burst %d)", cidr, rate, burst)
	} else {
		if err := xdp.RemoveRateLimitRule(m, cidr); err != nil {
			log.Printf("⚠️  Failed to remove rate limit rule %s: %v", cidr, err)
		} else {
			log.Printf("🚀 Removed rate limit: %s", cidr)
		}
	}

	// Update Config / 更新配置
	configPath := "/etc/netxfw/config.yaml"
	globalCfg, err := types.LoadGlobalConfig(configPath)
	if err == nil {
		newRules := []types.RateLimitRule{}
		modified := false
		targetCIDR := ensureCIDR(ip)

		for _, r := range globalCfg.RateLimit.Rules {
			if ensureCIDR(r.IP) == targetCIDR {
				if add {
					// Update / 更新
					if r.Rate != rate || r.Burst != burst {
						r.Rate = rate
						r.Burst = burst
						modified = true
					}
					newRules = append(newRules, r)
				} else {
					modified = true // Remove / 移除
				}
			} else {
				newRules = append(newRules, r)
			}
		}

		if add && !modified {
			found := false
			for _, r := range newRules {
				if ensureCIDR(r.IP) == targetCIDR {
					found = true
					break
				}
			}
			if !found {
				newRules = append(newRules, types.RateLimitRule{
					IP:    ip,
					Rate:  rate,
					Burst: burst,
				})
				modified = true
			}
		}

		if modified {
			globalCfg.RateLimit.Rules = newRules
			types.SaveGlobalConfig(configPath, globalCfg)
		}
	}
}

// SyncAutoBlock updates the auto-block setting in config.
// SyncAutoBlock 更新配置中的自动封禁设置。
func SyncAutoBlock(enable bool) {
	configPath := "/etc/netxfw/config.yaml"
	globalCfg, err := types.LoadGlobalConfig(configPath)
	if err == nil {
		globalCfg.RateLimit.AutoBlock = enable
		types.SaveGlobalConfig(configPath, globalCfg)
		log.Printf("🛡️ Auto Block set to: %v", enable)
	} else {
		log.Fatalf("❌ Failed to load config: %v", err)
	}
}

// SyncAutoBlockExpiry updates the auto-block expiry time in config.
// SyncAutoBlockExpiry 更新配置中的自动封禁过期时间。
func SyncAutoBlockExpiry(seconds uint32) {
	configPath := "/etc/netxfw/config.yaml"
	globalCfg, err := types.LoadGlobalConfig(configPath)
	if err == nil {
		globalCfg.RateLimit.AutoBlockExpiry = fmt.Sprintf("%ds", seconds)
		types.SaveGlobalConfig(configPath, globalCfg)
		log.Printf("🛡️ Auto Block Expiry set to: %d seconds", seconds)
	} else {
		log.Fatalf("❌ Failed to load config: %v", err)
	}
}

// ClearBlacklist clears all entries from lock_list.
// ClearBlacklist 清除 lock_list 中的所有条目。
func ClearBlacklist() {
	log.Println("🧹 Clearing blacklist...")

	// Clear Unified Map / 清除统一 Map
	m, err := ebpf.LoadPinnedMap("/sys/fs/bpf/netxfw/lock_list", nil)
	if err == nil {
		if _, err := xdp.ClearMap(m); err != nil {
			log.Printf("⚠️  Failed to clear blacklist: %v", err)
		} else {
			log.Println("✅ IPv4 Blacklist cleared.")
		}
		m.Close()
	} else {
		log.Printf("⚠️  Failed to load lock_list: %v", err)
	}

	// Clear persistence file / 清除持久化文件
	configPath := "/etc/netxfw/config.yaml"
	globalCfg, err := types.LoadGlobalConfig(configPath)
	if err == nil && globalCfg.Base.LockListFile != "" {
		if err := os.WriteFile(globalCfg.Base.LockListFile, []byte(""), 0644); err == nil {
			log.Printf("📄 Cleared persistence file: %s", globalCfg.Base.LockListFile)
		} else {
			log.Printf("⚠️  Failed to clear persistence file: %v", err)
		}
	}
}

// ImportLockListFromFile imports IPs from a file to the blacklist.
// ImportLockListFromFile 从文件导入 IP 到黑名单。
func ImportLockListFromFile(path string) {
	file, err := os.Open(path)
	if err != nil {
		log.Fatalf("❌ Failed to open file: %v", err)
	}
	defer file.Close()

	log.Printf("📦 Importing blacklist from %s...", path)
	scanner := bufio.NewScanner(file)
	count := 0

	// Use batch loading by reading all valid lines first / 首先读取所有有效行，使用批量加载
	var cidrs []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			cidrs = append(cidrs, line)
		}
	}

	m, _ := ebpf.LoadPinnedMap("/sys/fs/bpf/netxfw/lock_list", nil)
	if m != nil {
		defer m.Close()
	}

	// Prepare persistence update / 准备持久化更新
	configPath := "/etc/netxfw/config.yaml"
	globalCfg, _ := types.LoadGlobalConfig(configPath)
	var persistentLines []string
	if globalCfg != nil && globalCfg.Base.LockListFile != "" {
		// Read existing / 读取现有内容
		if content, err := os.ReadFile(globalCfg.Base.LockListFile); err == nil {
			lines := strings.Split(string(content), "\n")
			for _, l := range lines {
				if strings.TrimSpace(l) != "" {
					persistentLines = append(persistentLines, strings.TrimSpace(l))
				}
			}
		}
	}

	for _, cidr := range cidrs {
		// Check valid CIDR/IP / 检查有效的 CIDR/IP
		if !strings.Contains(cidr, "/") {
			if IsIPv6(cidr) {
				cidr += "/128"
			} else {
				cidr += "/32"
			}
		}

		// Update BPF / 更新 BPF
		if m != nil {
			if err := xdp.LockIP(m, cidr); err != nil {
				log.Printf("⚠️  Failed to lock %s: %v", cidr, err)
			} else {
				count++
			}
		}

		// Update persistent list / 更新持久化列表
		if globalCfg != nil && globalCfg.Base.PersistRules {
			persistentLines = append(persistentLines, cidr)
		}
	}

	// Save persistence / 保存持久化
	if globalCfg != nil && globalCfg.Base.PersistRules && globalCfg.Base.LockListFile != "" {
		// Merge/Deduplicate / 合并/去重
		merged, err := ipmerge.MergeCIDRsWithThreshold(persistentLines, globalCfg.Base.LockListMergeThreshold, globalCfg.Base.LockListV4Mask, globalCfg.Base.LockListV6Mask)
		if err != nil {
			merged = persistentLines
		}
		os.WriteFile(globalCfg.Base.LockListFile, []byte(strings.Join(merged, "\n")+"\n"), 0644)
		log.Printf("📄 Persisted %d rules to %s", len(merged), globalCfg.Base.LockListFile)
	}

	log.Printf("✅ Imported %d rules.", count)
}

// ImportWhitelistFromFile imports IPs from a file to the whitelist.
// ImportWhitelistFromFile 从文件导入 IP 到白名单。
func ImportWhitelistFromFile(path string) {
	file, err := os.Open(path)
	if err != nil {
		log.Fatalf("❌ Failed to open file: %v", err)
	}
	defer file.Close()

	log.Printf("📦 Importing whitelist from %s...", path)
	scanner := bufio.NewScanner(file)
	count := 0

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			// Format: IP or IP:Port / 格式：IP 或 IP:端口
			var ip string
			var port uint16

			// Handle IPv6 [IP]:Port / 处理 IPv6 [IP]:端口
			if strings.HasPrefix(line, "[") {
				end := strings.LastIndex(line, "]")
				if end != -1 {
					ip = line[1:end]
					if len(line) > end+2 && line[end+1] == ':' {
						fmt.Sscanf(line[end+2:], "%d", &port)
					}
				}
			} else {
				// Try to parse as IP:Port / 尝试解析为 IP:端口
				host, portStr, err := net.SplitHostPort(line)
				if err == nil {
					ip = host
					p, _ := strconv.Atoi(portStr)
					port = uint16(p)
				} else {
					ip = line
					port = 0
				}
			}

			SyncWhitelistMap(ip, port, true)
			count++
		}
	}
	log.Printf("✅ Imported %d whitelist rules.", count)
}

// ImportIPPortRulesFromFile imports IP+Port rules from a file.
// ImportIPPortRulesFromFile 从文件导入 IP+端口规则。
func ImportIPPortRulesFromFile(path string) {
	file, err := os.Open(path)
	if err != nil {
		log.Fatalf("❌ Failed to open file: %v", err)
	}
	defer file.Close()

	log.Printf("📦 Importing IP+Port rules from %s...", path)
	scanner := bufio.NewScanner(file)
	count := 0

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			// Format: IP Port Action (allow/deny) / 格式：IP 端口 动作 (allow/deny)
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				ip := parts[0]
				port, _ := strconv.Atoi(parts[1])
				actionStr := strings.ToLower(parts[2])
				action := uint8(2) // Deny
				if actionStr == "allow" {
					action = 1
				}

				SyncIPPortRule(ip, uint16(port), action, true)
				count++
			}
		}
	}
	log.Printf("✅ Imported %d IP+Port rules.", count)
}
