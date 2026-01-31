package base

import (
	"bufio"
	"log"
	"os"
	"strings"

	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/internal/xdp"
)

type BasePlugin struct {
	config *types.BaseConfig
}

func (p *BasePlugin) Name() string {
	return "base"
}

func (p *BasePlugin) Init(config *types.GlobalConfig) error {
	p.config = &config.Base
	return nil
}

func (p *BasePlugin) Start(manager *xdp.Manager) error {
	if p.config == nil {
		return nil
	}

	// 1. Set default deny
	if err := manager.SetDefaultDeny(p.config.DefaultDeny); err != nil {
		log.Printf("⚠️  [BasePlugin] Failed to set default deny: %v", err)
	}

	// 2. Apply whitelist
	for _, cidr := range p.config.Whitelist {
		if isIPv6(cidr) {
			xdp.AllowIP(manager.Whitelist6(), cidr)
		} else {
			xdp.AllowIP(manager.Whitelist(), cidr)
		}
	}

	// 3. Apply lock list from file if configured
	if p.config.LockListFile != "" {
		if _, err := os.Stat(p.config.LockListFile); err == nil {
			file, err := os.Open(p.config.LockListFile)
			if err == nil {
				scanner := bufio.NewScanner(file)
				count := 0
				for scanner.Scan() {
					line := strings.TrimSpace(scanner.Text())
					if line == "" || strings.HasPrefix(line, "#") {
						continue
					}
					if isIPv6(line) {
						xdp.LockIP(manager.LockList6(), line)
					} else {
						xdp.LockIP(manager.LockList(), line)
					}
					count++
				}
				file.Close()
				log.Printf("🛡️  [BasePlugin] Pre-loaded %d IPs/ranges from %s", count, p.config.LockListFile)
			}
		}
	}

	log.Printf("✅ [BasePlugin] Applied default_deny=%v and %d whitelist entries",
		p.config.DefaultDeny, len(p.config.Whitelist))
	return nil
}

func isIPv6(cidr string) bool {
	for i := 0; i < len(cidr); i++ {
		if cidr[i] == ':' {
			return true
		}
	}
	return false
}

func (p *BasePlugin) Stop() error {
	return nil
}

func (p *BasePlugin) DefaultConfig() interface{} {
	return types.BaseConfig{
		DefaultDeny:  false,
		Whitelist:    []string{"127.0.0.1/32"},
		LockListFile: "/etc/netxfw/lock.conf",
	}
}

func (p *BasePlugin) Validate(config *types.GlobalConfig) error {
	return nil
}
