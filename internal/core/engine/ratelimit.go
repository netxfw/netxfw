package engine

import (
	"fmt"
	"net"
	"time"

	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/pkg/sdk"
)

type RateLimitModule struct {
	config   *types.RateLimitConfig
	manager  sdk.ManagerInterface
	eventBus sdk.EventBus
	logger   sdk.Logger
	sdk      *sdk.SDK
	stopChan chan struct{}
	knownIPs map[string]bool
}

func (m *RateLimitModule) Name() string {
	return "ratelimit"
}

func (m *RateLimitModule) Init(cfg *types.GlobalConfig, s *sdk.SDK, logger sdk.Logger) error {
	m.config = &cfg.RateLimit
	m.manager = s.GetManager()
	m.eventBus = s.EventBus
	m.logger = logger
	m.sdk = s
	m.stopChan = make(chan struct{})
	m.knownIPs = make(map[string]bool)
	return nil
}

func (m *RateLimitModule) Start() error {
	m.logger.Infof("🚀 [Core] Starting RateLimit Module...")
	if err := m.Sync(); err != nil {
		return err
	}
	go m.monitorBlacklist()
	return nil
}

func (m *RateLimitModule) Reload(cfg *types.GlobalConfig) error {
	m.logger.Infof("🔄 [Core] Reloading RateLimit Module...")
	m.config = &cfg.RateLimit
	return m.Sync()
}

func (m *RateLimitModule) Stop() error {
	close(m.stopChan)
	return nil
}

func (m *RateLimitModule) monitorBlacklist() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopChan:
			return
		case <-ticker.C:
			// Poll blacklist to detect new blocks (e.g. from BPF auto-block)
			ips, _, err := m.sdk.Blacklist.List(0, "")
			if err != nil {
				continue
			}

			currentIPs := make(map[string]bool)
			for _, ip := range ips {
				currentIPs[ip.IP] = true
				if !m.knownIPs[ip.IP] {
					// New IP blocked!
					m.logger.Infof("🚫 [RateLimit] Detected new blocked IP: %s", ip.IP)
					if m.eventBus != nil {
						m.eventBus.Publish(sdk.NewEvent(sdk.EventTypeRateLimitBlock, "auto_block", ip.IP))
					}
				}
			}
			m.knownIPs = currentIPs
		}
	}
}

func (m *RateLimitModule) Sync() error {
	if m.config == nil {
		return nil
	}

	if err := m.manager.SetEnableRateLimit(m.config.Enabled); err != nil {
		m.logger.Warnf("⚠️  [RateLimit] Failed to set enable: %v", err)
	}
	if err := m.manager.SetAutoBlock(m.config.AutoBlock); err != nil {
		m.logger.Warnf("⚠️  [RateLimit] Failed to set auto-block: %v", err)
	}
	if m.config.AutoBlockExpiry != "" {
		if d, err := time.ParseDuration(m.config.AutoBlockExpiry); err == nil {
			m.manager.SetAutoBlockExpiry(d)
		}
	}

	// Sync Rate Limit Rules
	currentRules, _, err := m.manager.ListRateLimitRules(0, "")
	if err != nil {
		m.logger.Warnf("⚠️ [RateLimit] Failed to list current rules: %v", err)
		return fmt.Errorf("failed to list rate limit rules: %w", err)
	}

	desiredRules := make(map[string]types.RateLimitRule)
	for _, rule := range m.config.Rules {
		_, ipNet, err := net.ParseCIDR(rule.IP)
		if err != nil {
			ip := net.ParseIP(rule.IP)
			if ip != nil {
				desiredRules[ip.String()] = types.RateLimitRule{
					IP:    ip.String(),
					Rate:  rule.Rate,
					Burst: rule.Burst,
				}
			}
		} else {
			desiredRules[ipNet.String()] = types.RateLimitRule{
				IP:    ipNet.String(),
				Rate:  rule.Rate,
				Burst: rule.Burst,
			}
		}
	}

	for _, rule := range currentRules {
		// rule is RateLimitConf (struct), not pointer
		// We don't have IP in RateLimitConf returned by ListRateLimitRules currently
		// The map key is the IP.
		// Wait, ListRateLimitRules returns map[string]RateLimitConf
		// So we need to iterate the map
		_ = rule
	}

	// Fix: ListRateLimitRules returns map[string]RateLimitConf
	for ip := range currentRules {
		if _, exists := desiredRules[ip]; !exists {
			m.logger.Infof("➖ [RateLimit] Should remove rule for %s", ip)
			// m.manager.RemoveRateLimitRule(ip)
		}
	}

	for _, rule := range desiredRules {
		m.logger.Infof("➕ [RateLimit] Syncing rule for %s: %d/%d", rule.IP, rule.Rate, rule.Burst)
		m.manager.AddRateLimitRule(rule.IP, rule.Rate, rule.Burst)
	}
	return nil
}
