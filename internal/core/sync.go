package core

import (
	"fmt"
	"log"
	"os"
	"sort"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/livp123/netxfw/internal/config"
	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/internal/utils/iputil"
	"github.com/livp123/netxfw/internal/xdp"
)

// SyncToConfig dumps current BPF map states to configuration files.
// This is useful if the config files were lost or if changes were made directly to maps.
// SyncToConfig 将当前 BPF Map 状态转储到配置文件。
// 如果配置文件丢失或直接对 Map 进行了更改，此功能非常有用。
func SyncToConfig() {
	log.Println("🔄 Syncing BPF Maps to Configuration Files...")
	configPath := config.GetConfigPath()
	globalCfg, err := types.LoadGlobalConfig(configPath)
	if err != nil {
		log.Fatalf("❌ Failed to load config: %v", err)
	}

	// 1. Sync Blacklist (lock_list) -> rules.deny.txt (or configured file) / 同步黑名单
	syncBlacklistToConfig(globalCfg)

	// 2. Sync Whitelist (whitelist) -> config.yaml / 同步白名单
	syncWhitelistToConfig(globalCfg)

	// 3. Sync IP Port Rules -> config.yaml / 同步 IP 端口规则
	syncIPPortRulesToConfig(globalCfg)

	// 4. Sync Allowed Ports -> config.yaml / 同步允许的端口
	syncAllowedPortsToConfig(globalCfg)

	// 5. Sync Rate Limits -> config.yaml / 同步速率限制
	syncRateLimitsToConfig(globalCfg)

	// Save final config / 保存最终配置
	if err := types.SaveGlobalConfig(configPath, globalCfg); err != nil {
		log.Fatalf("❌ Failed to save config: %v", err)
	}
	log.Println("✅ Configuration files updated successfully.")
}

// SyncToMap applies the current configuration files to the BPF maps.
// This overwrites the runtime state with what is in the files.
// SyncToMap 将当前配置文件应用到 BPF Map。
// 这会用文件中的内容覆盖运行时状态。
func SyncToMap() {
	log.Println("🔄 Syncing Configuration Files to BPF Maps...")
	configPath := config.GetConfigPath()
	globalCfg, err := types.LoadGlobalConfig(configPath)
	if err != nil {
		log.Fatalf("❌ Failed to load config: %v", err)
	}

	// 1. Sync Blacklist / 同步黑名单
	if globalCfg.Base.LockListFile != "" {
		log.Printf("📥 Importing Blacklist from %s...", globalCfg.Base.LockListFile)
		ImportLockListFromFile(globalCfg.Base.LockListFile)
	}

	// 2. Sync Whitelist / 同步白名单
	log.Println("🧹 Clearing and reloading Whitelist...")
	if err := clearMapByName(config.MapWhitelist); err != nil {
		log.Printf("⚠️  Failed to clear whitelist: %v", err)
	}

	// Reload rules
	for _, ip := range globalCfg.Base.Whitelist {
		var port uint16
		cidr := ip

		// Try to parse as IP:Port / 尝试解析为 IP:Port
		host, p, err := iputil.ParseIPPort(ip)
		if err == nil {
			cidr = host
			port = p
		}

		SyncWhitelistMap(cidr, port, true)
	}

	// 3. Sync IP Port Rules / 同步 IP 端口规则
	log.Println("🧹 Clearing and reloading IP Port Rules...")
	if err := clearMapByName(config.MapIPPortRules); err != nil {
		log.Printf("⚠️  Failed to clear ip_port_rules: %v", err)
	}
	for _, r := range globalCfg.Port.IPPortRules {
		SyncIPPortRule(r.IP, r.Port, r.Action, true)
	}

	// 4. Sync Allowed Ports / 同步允许的端口
	log.Println("🧹 Clearing and reloading Allowed Ports...")
	if err := clearMapByName(config.MapAllowedPorts); err != nil {
		log.Printf("⚠️  Failed to clear allowed_ports: %v", err)
	}

	mAllowed, err := config.LoadMap(config.MapAllowedPorts)
	if err != nil {
		log.Printf("⚠️  Failed to load allowed_ports map: %v", err)
	} else {
		defer mAllowed.Close()
		for _, port := range globalCfg.Port.AllowedPorts {
			if err := xdp.AllowPort(mAllowed, port); err != nil {
				log.Printf("⚠️  Failed to allow port %d: %v", port, err)
			}
		}
	}

	// 5. Sync Rate Limits / 同步速率限制
	log.Println("🧹 Clearing and reloading Rate Limits...")
	if err := clearMapByName(config.MapRatelimitConfig); err != nil {
		log.Printf("⚠️  Failed to clear ratelimit_config: %v", err)
	}
	for _, r := range globalCfg.RateLimit.Rules {
		SyncRateLimitRule(r.IP, r.Rate, r.Burst, true)
	}

	log.Println("✅ BPF Maps synced from configuration.")
}

// Helpers / 辅助函数

func clearMapByName(mapName string) error {
	m, err := config.LoadMap(mapName)
	if err != nil {
		return err
	}
	defer m.Close()
	_, err = xdp.ClearMap(m)
	return err
}

func syncBlacklistToConfig(cfg *types.GlobalConfig) {
	m, err := config.LoadMap(config.MapLockList)
	if err != nil {
		log.Printf("⚠️  Failed to load whitelist map: %v", err)
		return
	}
	defer m.Close()

	ips, _, err := xdp.ListBlockedIPs(m, false, 0, "")
	if err != nil {
		log.Printf("⚠️  Failed to list blocked IPs: %v", err)
		return
	}

	// Also get dynamic lock list if exists / 如果存在，也获取动态锁定列表
	md, err := config.LoadMap(config.MapDynLockList)
	if err == nil {
		defer md.Close()
		dynIps, _, _ := xdp.ListBlockedIPs(md, false, 0, "")
		for _, ip := range dynIps {
			ips = append(ips, ip)
		}
	}

	// Extract just the IP strings / 仅提取 IP 字符串
	var ipStrings []string
	for _, ip := range ips {
		ipStrings = append(ipStrings, ip.IP)
	}

	sort.Strings(ipStrings)

	if cfg.Base.LockListFile != "" {
		err := os.WriteFile(cfg.Base.LockListFile, []byte(strings.Join(ipStrings, "\n")+"\n"), 0644)
		if err != nil {
			log.Printf("❌ Failed to write blacklist file: %v", err)
		} else {
			log.Printf("📄 Exported %d blacklist rules to %s", len(ips), cfg.Base.LockListFile)
		}
	}
}

func syncWhitelistToConfig(cfg *types.GlobalConfig) {
	m, err := config.LoadMap(config.MapWhitelist)
	if err != nil {
		log.Printf("⚠️  Failed to load whitelist map: %v", err)
		return
	}
	defer m.Close()

	ips, err := listWhitelistEntries(m)
	if err != nil {
		log.Printf("⚠️  Failed to list whitelist IPs: %v", err)
		return
	}

	cfg.Base.Whitelist = ips
	log.Printf("📄 Updated config whitelist with %d entries", len(ips))
}

func listWhitelistEntries(m *ebpf.Map) ([]string, error) {
	var ips []string
	iter := m.Iterate()
	var key xdp.NetXfwLpmKey
	var val xdp.NetXfwRuleValue

	for iter.Next(&key, &val) {
		ipStr := xdp.FormatLpmKey(&key)
		// val.Counter holds the port number / val.Counter 保存端口号
		if val.Counter > 1 {
			if strings.Contains(ipStr, ":") && !strings.Contains(ipStr, ".") {
				// IPv6
				ipStr = fmt.Sprintf("[%s]:%d", ipStr, val.Counter)
			} else {
				ipStr = fmt.Sprintf("%s:%d", ipStr, val.Counter)
			}
		}
		ips = append(ips, ipStr)
	}
	return ips, iter.Err()
}

func syncIPPortRulesToConfig(cfg *types.GlobalConfig) {
	m, err := config.LoadMap(config.MapIPPortRules)
	if err != nil {
		return
	}
	defer m.Close()

	var rules []types.IPPortRule
	iter := m.Iterate()
	var key xdp.NetXfwLpmIpPortKey
	var val xdp.NetXfwRuleValue

	for iter.Next(&key, &val) {
		ip := xdp.FormatIn6Addr(&key.Ip)
		rules = append(rules, types.IPPortRule{
			IP:     ip,
			Port:   key.Port,
			Action: uint8(val.Counter), // 1=Allow, 2=Deny / 1=允许, 2=拒绝
		})
	}
	cfg.Port.IPPortRules = rules
	log.Printf("📄 Updated config IP Port Rules with %d entries", len(rules))
}

func syncAllowedPortsToConfig(cfg *types.GlobalConfig) {
	m, err := config.LoadMap(config.MapAllowedPorts)
	if err != nil {
		return
	}
	defer m.Close()

	var ports []uint16
	iter := m.Iterate()
	var port uint16
	var val uint8

	for iter.Next(&port, &val) {
		ports = append(ports, port)
	}
	sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
	cfg.Port.AllowedPorts = ports
	log.Printf("📄 Updated config Allowed Ports with %d entries", len(ports))
}

func syncRateLimitsToConfig(cfg *types.GlobalConfig) {
	m, err := config.LoadMap(config.MapRatelimitConfig)
	if err != nil {
		return
	}
	defer m.Close()

	var rules []types.RateLimitRule
	iter := m.Iterate()
	var key xdp.NetXfwLpmKey
	var val struct {
		Rate  uint64
		Burst uint64
	}

	for iter.Next(&key, &val) {
		ip := xdp.FormatLpmKey(&key)
		rules = append(rules, types.RateLimitRule{
			IP:    ip,
			Rate:  val.Rate,
			Burst: val.Burst,
		})
	}
	cfg.RateLimit.Rules = rules
	log.Printf("📄 Updated config Rate Limits with %d entries", len(rules))
}
