package engine

import (
	"fmt"
	"net"
	"time"

	sdk "github.com/netxfw/netxfw/pkg/sdk"
)

type RateLimitModule struct {
	config   *sdk.RateLimitConfig
	security sdk.SecurityAPI
	rule     sdk.RuleAPI
	eventBus sdk.EventBus
	logger   sdk.Logger
	sdk      *sdk.SDK
	stopChan chan struct{}
	knownIPs map[string]bool
}

func (m *RateLimitModule) Name() string {
	return "ratelimit"
}

func (m *RateLimitModule) Init(cfg *sdk.GlobalConfig, s *sdk.SDK, logger sdk.Logger) error {
	m.config = &cfg.RateLimit
	m.security = s.Security
	m.rule = s.Rule
	m.eventBus = s.EventBus
	m.logger = logger
	m.sdk = s
	m.stopChan = make(chan struct{})
	m.knownIPs = make(map[string]bool)
	return nil
}

func (m *RateLimitModule) Start() error {
	m.logger.Infof("[START] [Core] Starting RateLimit Module...")
	if err := m.Sync(); err != nil {
		return err
	}
	go m.monitorBlacklist()
	return nil
}

func (m *RateLimitModule) Reload(cfg *sdk.GlobalConfig) error {
	m.logger.Infof("[RELOAD] [Core] Reloading RateLimit Module...")
	m.config = &cfg.RateLimit
	return m.Sync()
}

func (m *RateLimitModule) Stop() error {
	if m.stopChan != nil {
		close(m.stopChan)
	}
	return nil
}

func (m *RateLimitModule) monitorBlacklist() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	var lastKnownCount int
	for {
		select {
		case <-m.stopChan:
			return
		case <-ticker.C:
			dynamicList, totalCount, err := m.sdk.Blacklist.ListDynamic(0, "")
			if err != nil {
				continue
			}

			if totalCount == lastKnownCount {
				continue
			}
			lastKnownCount = totalCount

			currentIPs := make(map[string]bool, len(dynamicList))
			for _, ip := range dynamicList {
				currentIPs[ip.IP] = true
				if !m.knownIPs[ip.IP] {
					m.logger.Infof("[BLOCK] [RateLimit] Detected new blocked IP: %s", ip.IP)
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

	if err := m.security.SetEnableRateLimit(m.config.Enabled); err != nil {
		m.logger.Warnf("[WARN]  [RateLimit] Failed to set enable: %v", err)
	}
	if err := m.security.SetAutoBlock(m.config.AutoBlock); err != nil {
		m.logger.Warnf("[WARN]  [RateLimit] Failed to set auto-block: %v", err)
	}
	if m.config.AutoBlockExpiry != "" {
		if d, err := time.ParseDuration(m.config.AutoBlockExpiry); err == nil {
			if err := m.security.SetAutoBlockExpiry(d); err != nil {
				m.logger.Warnf("[WARN]  [RateLimit] Failed to set auto-block expiry: %v", err)
			}
		}
	}

	currentRules, _, err := m.rule.ListRateLimitRules(0, "")
	if err != nil {
		m.logger.Warnf("[WARN] [RateLimit] Failed to list current rules: %v", err)
		return fmt.Errorf("failed to list rate limit rules: %w", err)
	}

	desiredRules := make(map[string]sdk.RateLimitRule)
	for _, rule := range m.config.Rules {
		_, ipNet, err := net.ParseCIDR(rule.IP)
		if err != nil {
			ip := net.ParseIP(rule.IP)
			if ip != nil {
				desiredRules[ip.String()] = sdk.RateLimitRule{
					IP:    ip.String(),
					Rate:  rule.Rate,
					Burst: rule.Burst,
				}
			}
		} else {
			desiredRules[ipNet.String()] = sdk.RateLimitRule{
				IP:    ipNet.String(),
				Rate:  rule.Rate,
				Burst: rule.Burst,
			}
		}
	}

	for ip := range currentRules {
		if _, exists := desiredRules[ip]; !exists {
			m.logger.Infof("➖ [RateLimit] Should remove rule for %s", ip)
		}
	}

	for _, rule := range desiredRules {
		m.logger.Infof("➕ [RateLimit] Syncing rule for %s: %d/%d", rule.IP, rule.Rate, rule.Burst)
		if err := m.rule.AddRateLimitRule(rule.IP, rule.Rate, rule.Burst); err != nil {
			m.logger.Warnf("[WARN] [RateLimit] Failed to add rule for %s: %v", rule.IP, err)
		}
	}
	return nil
}
