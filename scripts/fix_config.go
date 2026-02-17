package main

import (
	"fmt"
	"os"
	"time"

	"github.com/livp123/netxfw/internal/plugins/types"
	"gopkg.in/yaml.v3"
)

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
	denyRulesPath := "/root/netxfw/rules.deny.txt"

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

	var cfg types.GlobalConfig
	if unmarshalErr := yaml.Unmarshal(data, &cfg); unmarshalErr != nil {
		fmt.Printf("Error unmarshaling config: %v\n", unmarshalErr)
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
		cfg.Port.IPPortRules = append(cfg.Port.IPPortRules, types.IPPortRule{
			IP:     "::/0",
			Port:   22,
			Action: 1,
		})
		fixesApplied++
	}

	// Backup and clear the deny rules file
	targetDenyPath := denyRulesPath
	if cfg.Base.LockListFile != "" {
		targetDenyPath = cfg.Base.LockListFile
	}

	if _, statErr := os.Stat(targetDenyPath); statErr == nil {
		if backupErr := backupFile(targetDenyPath); backupErr != nil {
			fmt.Printf("Warning: Could not create backup of deny rules: %v\n", backupErr)
		}
	}

	if writeErr := os.WriteFile(targetDenyPath, []byte("# netxfw rules - empty\n"), 0644); writeErr != nil {
		fmt.Printf("Warning: Could not clear deny rules file: %v\n", writeErr)
	} else {
		fmt.Printf("Cleared deny rules file: %s\n", targetDenyPath)
		fixesApplied++
	}

	// Marshal the fixed configuration
	newData, err := yaml.Marshal(&cfg)
	if err != nil {
		fmt.Printf("Error marshaling config: %v\n", err)
		os.Exit(1)
	}

	// Write the fixed configuration back to file
	if writeErr := os.WriteFile(configPath, newData, 0644); writeErr != nil {
		fmt.Printf("Error writing config: %v\n", writeErr)
		os.Exit(1)
	}

	fmt.Printf("Configuration fixed successfully. Applied %d fixes.\n", fixesApplied)
	fmt.Printf("Updated config saved to: %s\n", configPath)
}
