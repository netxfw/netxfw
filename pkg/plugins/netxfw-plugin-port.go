package plugins

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/livp123/netxfw/internal/xdp"
	"github.com/mitchellh/mapstructure"
)

type PortRule struct {
	Port      uint16     `mapstructure:"port"`
	Protocol  string     `mapstructure:"protocol"`
	Action    string     `mapstructure:"action"`
	ExpiresAt *time.Time `mapstructure:"expires_at"`
}

type IPPortRule struct {
	CIDR      string     `mapstructure:"cidr"`
	Port      uint16     `mapstructure:"port"`
	Protocol  string     `mapstructure:"protocol"`
	Action    string     `mapstructure:"action"`
	ExpiresAt *time.Time `mapstructure:"expires_at"`
}

type NetXfwPortConfig struct {
	Rules       []PortRule   `mapstructure:"rules"`
	IPPortRules []IPPortRule `mapstructure:"ip_port_rules"`
}

type NetXfwPortPlugin struct {
	manager *xdp.Manager
	configs []NetXfwPortConfig
}

func (p *NetXfwPortPlugin) Name() string {
	return "netxfw-plugins-port"
}

func (p *NetXfwPortPlugin) Description() string {
	return "Advanced port management with IP+Port rules and default deny support"
}

func (p *NetXfwPortPlugin) Init(manager *xdp.Manager, config interface{}) error {
	p.manager = manager
	if config == nil {
		return nil
	}

	// Use mapstructure to decode the config / 使用 mapstructure 解码配置
	err := mapstructure.Decode(config, &p.configs)
	if err != nil {
		return fmt.Errorf("failed to decode netxfw-plugins-port config: %w", err)
	}

	return nil
}

func (p *NetXfwPortPlugin) Start() error {
	log.Println("🔌 Starting NetXfw Port Plugin...")

	// 1. Enable Default Deny if any rules are present
	if len(p.configs) > 0 {
		log.Printf("🛡️  Enabling Default Deny (Rules count: %d)", len(p.configs))
		if err := p.manager.SetDefaultDeny(true); err != nil {
			return fmt.Errorf("failed to set default deny: %w", err)
		}
	} else {
		log.Println("ℹ️  No port rules found, Default Deny remains disabled.")
	}

	now := time.Now()
	for _, cfg := range p.configs {
		// 2. Global Port Rules
		for _, rule := range cfg.Rules {
			if rule.ExpiresAt != nil && rule.ExpiresAt.Before(now) {
				continue
			}
			if rule.Action == "allow" {
				if err := p.manager.AllowPort(rule.Port, rule.ExpiresAt); err != nil {
					log.Printf("⚠️  Failed to allow port %d: %v", rule.Port, err)
				}
			}
		}

		// 3. IP+Port Rules
		for _, rule := range cfg.IPPortRules {
			if rule.ExpiresAt != nil && rule.ExpiresAt.Before(now) {
				continue
			}
			// Support both CIDR and single IP / 支持 CIDR 和单个 IP
			cidr := rule.CIDR
			if !net.IP(cidr).IsUnspecified() && net.ParseIP(cidr) != nil {
				if net.ParseIP(cidr).To4() != nil {
					cidr += "/32"
				} else {
					cidr += "/128"
				}
			}

			_, ipNet, err := net.ParseCIDR(cidr)
			if err != nil {
				log.Printf("⚠️  Failed to parse CIDR %s: %v", cidr, err)
				continue
			}

			var action uint8
			if rule.Action == "allow" {
				action = 1
			} else {
				action = 2 // deny
			}

			if err := p.manager.AddIPPortRule(ipNet, rule.Port, action, rule.ExpiresAt); err != nil {
				log.Printf("⚠️  Failed to add IP+Port rule (%s:%d): %v", cidr, rule.Port, err)
			}
		}
	}

	log.Println("✅ NetXfw Port Plugin started.")
	return nil
}

func (p *NetXfwPortPlugin) Stop() error {
	log.Println("🔌 Stopping NetXfw Port Plugin...")
	// Disable Default Deny
	_ = p.manager.SetDefaultDeny(false)
	return nil
}

func init() {
	Register(&NetXfwPortPlugin{})
}
