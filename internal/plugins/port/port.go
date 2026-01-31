package port

import (
	"log"
	"net"

	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/internal/xdp"
)

type PortPlugin struct {
	config *types.PortConfig
}

func (p *PortPlugin) Name() string {
	return "port"
}

func (p *PortPlugin) Init(config *types.GlobalConfig) error {
	p.config = &config.Port
	return nil
}

func (p *PortPlugin) Start(manager *xdp.Manager) error {
	if p.config == nil {
		return nil
	}

	// Apply global allowed ports
	for _, pPort := range p.config.AllowedPorts {
		if err := manager.AllowPort(pPort, nil); err != nil {
			log.Printf("⚠️  [PortPlugin] Failed to allow port %d: %v", pPort, err)
		}
	}

	// Apply IP+Port rules
	for _, rule := range p.config.IPPortRules {
		_, ipNet, err := net.ParseCIDR(rule.IP)
		if err != nil {
			ip := net.ParseIP(rule.IP)
			if ip == nil {
				log.Printf("⚠️  [PortPlugin] Invalid IP: %s", rule.IP)
				continue
			}
			mask := net.CIDRMask(32, 32)
			if ip.To4() == nil {
				mask = net.CIDRMask(128, 128)
			}
			ipNet = &net.IPNet{IP: ip, Mask: mask}
		}

		if err := manager.AddIPPortRule(ipNet, rule.Port, rule.Action, nil); err != nil {
			log.Printf("⚠️  [PortPlugin] Failed to add IP+Port rule (%s:%d): %v", rule.IP, rule.Port, err)
		}
	}

	log.Printf("✅ [PortPlugin] Applied %d global ports and %d IP+Port rules",
		len(p.config.AllowedPorts), len(p.config.IPPortRules))
	return nil
}

func (p *PortPlugin) Stop() error {
	return nil
}

func (p *PortPlugin) DefaultConfig() interface{} {
	return types.PortConfig{
		AllowedPorts: []uint16{80, 443},
		IPPortRules:  []types.IPPortRule{},
	}
}

func (p *PortPlugin) Validate(config *types.GlobalConfig) error {
	return nil
}
