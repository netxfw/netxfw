package core

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/livp123/netxfw/internal/config"
	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/internal/utils/iputil"
	"github.com/livp123/netxfw/internal/utils/logger"
)

// SyncToConfig dumps current BPF map states to configuration files.
// This is useful if the config files were lost or if changes were made directly to maps.
// SyncToConfig 将当前 BPF Map 状态转储到配置文件。
// 如果配置文件丢失或直接对 Map 进行了更改，此功能非常有用。
func SyncToConfig(ctx context.Context, mgr XDPManager) error {
	log := logger.Get(ctx)
	log.Info("🔄 Syncing BPF Maps to Configuration Files...")
	configPath := config.GetConfigPath()
	globalCfg, err := types.LoadGlobalConfig(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %v", err)
	}

	// 1. Sync Blacklist (lock_list) -> rules.deny.txt (or configured file) / 同步黑名单
	syncBlacklistToConfig(ctx, mgr, globalCfg)

	// 2. Sync Whitelist (whitelist) -> config.yaml / 同步白名单
	syncWhitelistToConfig(ctx, mgr, globalCfg)

	// 3. Sync IP Port Rules -> config.yaml / 同步 IP 端口规则
	syncIPPortRulesToConfig(ctx, mgr, globalCfg)

	// 4. Sync Allowed Ports -> config.yaml / 同步允许的端口
	syncAllowedPortsToConfig(ctx, mgr, globalCfg)

	// 5. Sync Rate Limits -> config.yaml / 同步速率限制
	syncRateLimitsToConfig(ctx, mgr, globalCfg)

	// Save final config / 保存最终配置
	if err := types.SaveGlobalConfig(configPath, globalCfg); err != nil {
		return fmt.Errorf("failed to save config: %v", err)
	}
	log.Info("✅ Configuration files updated successfully.")
	return nil
}

// SyncToMap applies the current configuration files to the BPF maps.
// This overwrites the runtime state with what is in the files.
// SyncToMap 将当前配置文件应用到 BPF Map。
// 这会用文件中的内容覆盖运行时状态。
func SyncToMap(ctx context.Context, mgr XDPManager) error {
	log := logger.Get(ctx)
	log.Info("🔄 Syncing Configuration Files to BPF Maps...")
	configPath := config.GetConfigPath()
	globalCfg, err := types.LoadGlobalConfig(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %v", err)
	}

	// 1. Sync Blacklist / 同步黑名单
	if globalCfg.Base.LockListFile != "" {
		log.Infof("📥 Importing Blacklist from %s...", globalCfg.Base.LockListFile)
		// ImportLockListFromFile needs to be refactored or we use LockIP loop
		// For now, let's assume we read file and loop LockIP
		// ImportLockListFromFile(globalCfg.Base.LockListFile)
		if err := importLockListFromFile(ctx, mgr, globalCfg.Base.LockListFile); err != nil {
			log.Errorf("⚠️ Failed to import lock list: %v", err)
		}
	}

	// 2. Sync Whitelist / 同步白名单
	log.Info("🧹 Clearing and reloading Whitelist...")
	if err := mgr.ClearWhitelist(); err != nil {
		log.Errorf("⚠️  Failed to clear whitelist: %v", err)
	}

	// Reload rules / 重新加载规则
	for _, ip := range globalCfg.Base.Whitelist {
		var port uint16
		cidr := ip

		// Try to parse as IP:Port / 尝试解析为 IP:Port
		host, p, err := iputil.ParseIPPort(ip)
		if err == nil {
			cidr = host
			port = p
		}

		if err := mgr.AddWhitelistIP(cidr, port); err != nil {
			log.Errorf("⚠️ Failed to sync whitelist rule %s: %v", ip, err)
		}
	}

	// 3. Sync IP Port Rules / 同步 IP 端口规则
	log.Info("🧹 Clearing and reloading IP Port Rules...")
	if err := mgr.ClearIPPortRules(); err != nil {
		log.Errorf("⚠️  Failed to clear ip_port_rules: %v", err)
	}
	for _, r := range globalCfg.Port.IPPortRules {
		if err := mgr.AddIPPortRule(r.IP, r.Port, r.Action); err != nil {
			log.Errorf("⚠️ Failed to sync ip_port_rule %s:%d: %v", r.IP, r.Port, err)
		}
	}

	// 4. Sync Allowed Ports / 同步允许的端口
	log.Info("🧹 Clearing and reloading Allowed Ports...")
	if err := mgr.ClearAllowedPorts(); err != nil {
		log.Errorf("⚠️  Failed to clear allowed_ports: %v", err)
	}

	for _, port := range globalCfg.Port.AllowedPorts {
		if err := mgr.AllowPort(port); err != nil {
			log.Errorf("⚠️  Failed to allow port %d: %v", port, err)
		}
	}

	// 5. Sync Rate Limits / 同步速率限制
	log.Info("🧹 Clearing and reloading Rate Limits...")
	if err := mgr.ClearRateLimitRules(); err != nil {
		log.Errorf("⚠️  Failed to clear ratelimit_config: %v", err)
	}
	for _, r := range globalCfg.RateLimit.Rules {
		if err := mgr.AddRateLimitRule(r.IP, r.Rate, r.Burst); err != nil {
			log.Errorf("⚠️  Failed to add rate limit rule: %v", err)
		}
	}

	log.Info("✅ BPF Maps synced from configuration.")
	return nil
}

// Helpers / 辅助函数

func importLockListFromFile(ctx context.Context, mgr XDPManager, filePath string) error {
	// Read file content / 读取文件内容
	content, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if err := mgr.AddBlacklistIP(line); err != nil {
			logger.Get(ctx).Warnf("Failed to lock IP %s: %v", line, err)
		}
	}
	return nil
}

func syncBlacklistToConfig(ctx context.Context, mgr XDPManager, cfg *types.GlobalConfig) {
	log := logger.Get(ctx)

	// List blocked IPs / 列出被阻止的 IP
	ips, _, err := mgr.ListBlacklistIPs(0, "")
	if err != nil {
		log.Errorf("⚠️  Failed to list blocked IPs: %v", err)
		return
	}

	// Also get dynamic lock list if exists / 如果存在，也获取动态锁定列表
	dynIps, _, _ := mgr.ListDynamicBlacklistIPs(0, "")
	for _, ip := range dynIps {
		ips = append(ips, ip)
	}

	// Extract just the IP strings / 仅提取 IP 字符串
	var ipStrings []string
	for _, ip := range ips {
		ipStrings = append(ipStrings, ip.IP)
	}

	// Sort for consistency / 排序以保持一致性
	sort.Strings(ipStrings)

	if cfg.Base.LockListFile != "" {
		err := os.WriteFile(cfg.Base.LockListFile, []byte(strings.Join(ipStrings, "\n")+"\n"), 0644)
		if err != nil {
			log.Errorf("❌ Failed to write blacklist file: %v", err)
		} else {
			log.Infof("📄 Exported %d blacklist rules to %s", len(ips), cfg.Base.LockListFile)
		}
	}
}

func syncWhitelistToConfig(ctx context.Context, mgr XDPManager, cfg *types.GlobalConfig) {
	log := logger.Get(ctx)

	ips, _, err := mgr.ListWhitelistIPs(0, "")
	if err != nil {
		log.Errorf("⚠️  Failed to list whitelist IPs: %v", err)
		return
	}

	cfg.Base.Whitelist = ips
	log.Infof("📄 Updated config whitelist with %d entries", len(ips))
}

func syncIPPortRulesToConfig(ctx context.Context, mgr XDPManager, cfg *types.GlobalConfig) {
	log := logger.Get(ctx)
	rules, _, err := mgr.ListIPPortRules(false, 0, "")
	if err != nil {
		log.Errorf("⚠️ Failed to list IP Port Rules: %v", err)
		return
	}

	var configRules []types.IPPortRule
	for _, r := range rules {
		configRules = append(configRules, types.IPPortRule{
			IP:     r.IP,
			Port:   r.Port,
			Action: r.Action,
		})
	}
	cfg.Port.IPPortRules = configRules
	log.Infof("📄 Updated config IP Port Rules with %d entries", len(configRules))
}

func syncAllowedPortsToConfig(ctx context.Context, mgr XDPManager, cfg *types.GlobalConfig) {
	log := logger.Get(ctx)
	ports, err := mgr.ListAllowedPorts()
	if err != nil {
		log.Errorf("⚠️ Failed to list allowed ports: %v", err)
		return
	}

	sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
	cfg.Port.AllowedPorts = ports
	log.Infof("📄 Updated config Allowed Ports with %d entries", len(ports))
}

func syncRateLimitsToConfig(ctx context.Context, mgr XDPManager, cfg *types.GlobalConfig) {
	log := logger.Get(ctx)
	rulesMap, _, err := mgr.ListRateLimitRules(0, "")
	if err != nil {
		log.Errorf("⚠️ Failed to list rate limit rules: %v", err)
		return
	}

	var rules []types.RateLimitRule
	for ip, val := range rulesMap {
		rules = append(rules, types.RateLimitRule{
			IP:    ip,
			Rate:  val.Rate,
			Burst: val.Burst,
		})
	}
	cfg.RateLimit.Rules = rules
	log.Infof("📄 Updated config Rate Limits with %d entries", len(rules))
}
