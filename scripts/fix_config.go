package main

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the netxfw configuration structure
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

func backupFile(filePath string) error {
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil // File doesn't exist, no need to backup
	}

	backupPath := filePath + ".backup." + time.Now().Format("20060102_150405")
	source, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer source.Close()

	destination, err := os.Create(backupPath)
	if err != nil {
		return err
	}
	defer destination.Close()

	_, err = destination.ReadFrom(source)
	if err != nil {
		return err
	}

	fmt.Printf("Backed up %s to %s\n", filePath, backupPath)
	return nil
}

func main() {
	configPath := "/etc/netxfw/config.yaml"
	denyRulesPath := "/etc/netxfw/rules.deny.txt"

	// Check if command line argument is provided for config path
	if len(os.Args) > 1 {
		configPath = os.Args[1]
	}

	// Verify config file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		fmt.Printf("Config file does not exist: %s\n", configPath)
		os.Exit(1)
	}

	// Backup the original config file
	if err := backupFile(configPath); err != nil {
		fmt.Printf("Warning: Could not create backup: %v\n", err)
	}

	// Read the configuration file
	data, err := os.ReadFile(configPath)
	if err != nil {
		fmt.Printf("Error reading config: %v\n", err)
		os.Exit(1)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		fmt.Printf("Error unmarshaling config: %v\n", err)
		os.Exit(1)
	}

	fixesApplied := 0

	// 1. Clear whitelist placeholders if they exist
	if len(cfg.Base.Whitelist) > 0 {
		fmt.Printf("Clearing %d whitelist entries\n", len(cfg.Base.Whitelist))
		cfg.Base.Whitelist = []string{}
		fixesApplied++
	}

	// 2. Fix Conntrack timeouts
	tcpTimeoutChanged := false
	udpTimeoutChanged := false

	if cfg.Conntrack.TCPTimeout == "" || cfg.Conntrack.TCPTimeout == "0s" {
		fmt.Println("Fixing TCP timeout (was empty or 0s)")
		cfg.Conntrack.TCPTimeout = "30m"
		tcpTimeoutChanged = true
	}

	if cfg.Conntrack.UDPTimeout == "" || cfg.Conntrack.UDPTimeout == "0s" {
		fmt.Println("Fixing UDP timeout (was empty or 0s)")
		cfg.Conntrack.UDPTimeout = "5m"
		udpTimeoutChanged = true
	}

	if tcpTimeoutChanged || udpTimeoutChanged {
		fixesApplied++
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
		fmt.Println("Adding IPv6 SSH rule (::/0:22 allow)")
		cfg.Port.IPPortRules = append(cfg.Port.IPPortRules, struct {
			IP     string `yaml:"ip"`
			Port   uint16 `yaml:"port"`
			Action uint8  `yaml:"action"`
		}{
			IP:     "::/0",
			Port:   22,
			Action: 1,
		})
		fixesApplied++
	}

	// Backup and clear the deny rules file
	if _, err := os.Stat(denyRulesPath); err == nil {
		if err := backupFile(denyRulesPath); err != nil {
			fmt.Printf("Warning: Could not create backup of deny rules: %v\n", err)
		}
	}

	if err := os.WriteFile(denyRulesPath, []byte("# netxfw rules - empty\n"), 0644); err != nil {
		fmt.Printf("Warning: Could not clear deny rules file: %v\n", err)
	} else {
		fmt.Println("Cleared deny rules file")
		fixesApplied++
	}

	// Marshal the fixed configuration
	newData, err := yaml.Marshal(&cfg)
	if err != nil {
		fmt.Printf("Error marshaling config: %v\n", err)
		os.Exit(1)
	}

	// Write the fixed configuration back to file
	if err := os.WriteFile(configPath, newData, 0644); err != nil {
		fmt.Printf("Error writing config: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Configuration fixed successfully. Applied %d fixes.\n", fixesApplied)
	fmt.Printf("Updated config saved to: %s\n", configPath)
}
