package main

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Base struct {
		AllowICMP          bool     `yaml:"allow_icmp"`
		AllowReturnTraffic bool     `yaml:"allow_return_traffic"`
		BogonFilter        bool     `yaml:"bogon_filter"`
		CleanupInterval    string   `yaml:"cleanup_interval"`
		DefaultDeny        bool     `yaml:"default_deny"`
		DropFragments      bool     `yaml:"drop_fragments"`
		EnableAFXDP        bool     `yaml:"enable_af_xdp"`
		EnableExpiry       bool     `yaml:"enable_expiry"`
		ICMPBurst          int      `yaml:"icmp_burst"`
		ICMPRate           int      `yaml:"icmp_rate"`
		LockListBinary     string   `yaml:"lock_list_binary"`
		LockListFile       string   `yaml:"lock_list_file"`
		PersistRules       bool     `yaml:"persist_rules"`
		StrictProtocol     bool     `yaml:"strict_protocol"`
		StrictTCP          bool     `yaml:"strict_tcp"`
		SynLimit           bool     `yaml:"syn_limit"`
		Whitelist          []string `yaml:"whitelist"`
	} `yaml:"base"`
	Capacity struct {
		AllowedPorts uint32 `yaml:"allowed_ports"`
		Conntrack    uint32 `yaml:"conntrack"`
		DynLockList  uint32 `yaml:"dyn_lock_list"`
		IPPortRules  uint32 `yaml:"ip_port_rules"`
		LockList     uint32 `yaml:"lock_list"`
		Whitelist    uint32 `yaml:"whitelist"`
	} `yaml:"capacity"`
	Conntrack struct {
		Enabled    bool   `yaml:"enabled"`
		MaxEntries uint32 `yaml:"max_entries"`
		TCPTimeout string `yaml:"tcp_timeout"`
		UDPTimeout string `yaml:"udp_timeout"`
	} `yaml:"conntrack"`
	Port struct {
		AllowedPorts []uint16 `yaml:"allowed_ports"`
		IPPortRules  []struct {
			IP     string `yaml:"ip"`
			Port   uint16 `yaml:"port"`
			Action uint8  `yaml:"action"`
		} `yaml:"ip_port_rules"`
	} `yaml:"port"`
	RateLimit struct {
		AutoBlock       bool   `yaml:"auto_block"`
		AutoBlockExpiry string `yaml:"auto_block_expiry"`
		Enabled         bool   `yaml:"enabled"`
		Rules           []struct {
			IP    string `yaml:"ip"`
			Rate  uint64 `yaml:"rate"`
			Burst uint64 `yaml:"burst"`
		} `yaml:"rules"`
	} `yaml:"rate_limit"`
	Metrics map[string]interface{} `yaml:"metrics"`
	Web     map[string]interface{} `yaml:"web"`
}

func main() {
	data, err := os.ReadFile("/etc/netxfw/config.yaml")
	if err != nil {
		fmt.Printf("Error reading config: %v\n", err)
		return
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		fmt.Printf("Error unmarshaling config: %v\n", err)
		return
	}

	// 1. Clear whitelist placeholders
	cfg.Base.Whitelist = []string{}

	// 2. Fix Conntrack timeouts
	if cfg.Conntrack.TCPTimeout == "" || cfg.Conntrack.TCPTimeout == "0s" {
		cfg.Conntrack.TCPTimeout = "30m"
	}
	if cfg.Conntrack.UDPTimeout == "" || cfg.Conntrack.UDPTimeout == "0s" {
		cfg.Conntrack.UDPTimeout = "5m"
	}

	// 3. Ensure IPv6 SSH rule is present
	hasIPv6SSH := false
	for _, r := range cfg.Port.IPPortRules {
		if (r.IP == "::/0" || r.IP == "::") && r.Port == 22 {
			hasIPv6SSH = true
			break
		}
	}
	if !hasIPv6SSH {
		cfg.Port.IPPortRules = append(cfg.Port.IPPortRules, struct {
			IP     string `yaml:"ip"`
			Port   uint16 `yaml:"port"`
			Action uint8  `yaml:"action"`
		}{
			IP:     "::/0",
			Port:   22,
			Action: 1,
		})
	}

	// 3. Clear lock list file content to remove "1.1.1.1" and "8.8.8.8"
	_ = os.WriteFile("/etc/netxfw/rules.deny.txt", []byte("# netxfw rules - empty\n"), 0644)

	newData, err := yaml.Marshal(&cfg)
	if err != nil {
		fmt.Printf("Error marshaling config: %v\n", err)
		return
	}

	if err := os.WriteFile("/etc/netxfw/config.yaml", newData, 0644); err != nil {
		fmt.Printf("Error writing config: %v\n", err)
		return
	}

	fmt.Println("Config updated successfully")
}
