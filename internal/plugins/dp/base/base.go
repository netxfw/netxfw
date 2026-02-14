package base

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	nxfwbin "github.com/livp123/netxfw/internal/binary"
	"github.com/livp123/netxfw/internal/config"
	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/internal/utils/ipmerge"
	"github.com/livp123/netxfw/internal/utils/iputil"
	"github.com/livp123/netxfw/internal/xdp"
	"github.com/livp123/netxfw/pkg/sdk"
)

type BasePlugin struct {
	config *types.BaseConfig
}

func (p *BasePlugin) Name() string {
	return "base"
}

func (p *BasePlugin) Init(ctx *sdk.PluginContext) error {
	p.config = &ctx.Config.Base
	return nil
}

func (p *BasePlugin) Reload(ctx *sdk.PluginContext) error {
	log.Println("🔄 [BasePlugin] Reloading configuration (Full Sync)...")
	if err := p.Init(ctx); err != nil {
		return err
	}
	return p.Sync(ctx.Manager)
}

func (p *BasePlugin) Start(ctx *sdk.PluginContext) error {
	log.Println("🚀 [BasePlugin] Starting...")
	return p.Sync(ctx.Manager)
}

func (p *BasePlugin) Sync(manager *xdp.Manager) error {
	if p.config == nil {
		return nil
	}

	// 1. Set default deny and return traffic
	if err := manager.SetDefaultDeny(p.config.DefaultDeny); err != nil {
		log.Printf("⚠️  [BasePlugin] Failed to set default deny: %v", err)
	}
	if err := manager.SetAllowReturnTraffic(p.config.AllowReturnTraffic); err != nil {
		log.Printf("⚠️  [BasePlugin] Failed to set allow return traffic: %v", err)
	}
	if err := manager.SetAllowICMP(p.config.AllowICMP); err != nil {
		log.Printf("⚠️  [BasePlugin] Failed to set allow ICMP: %v", err)
	}
	if err := manager.SetEnableAFXDP(p.config.EnableAFXDP); err != nil {
		log.Printf("⚠️  [BasePlugin] Failed to set enable AF_XDP: %v", err)
	}
	if err := manager.SetStrictProtocol(p.config.StrictProtocol); err != nil {
		log.Printf("⚠️  [BasePlugin] Failed to set strict protocol: %v", err)
	}
	if err := manager.SetDropFragments(p.config.DropFragments); err != nil {
		log.Printf("⚠️  [BasePlugin] Failed to set drop fragments: %v", err)
	}
	if err := manager.SetStrictTCP(p.config.StrictTCP); err != nil {
		log.Printf("⚠️  [BasePlugin] Failed to set strict TCP: %v", err)
	}
	if err := manager.SetSYNLimit(p.config.SYNLimit); err != nil {
		log.Printf("⚠️  [BasePlugin] Failed to set SYN limit: %v", err)
	}
	if p.config.ICMPRate > 0 && p.config.ICMPBurst > 0 {
		if err := manager.SetICMPRateLimit(p.config.ICMPRate, p.config.ICMPBurst); err != nil {
			log.Printf("⚠️  [BasePlugin] Failed to set ICMP rate limit: %v", err)
		} else {
			log.Printf("✅ [BasePlugin] ICMP rate limit set to %d/s (burst: %d)", p.config.ICMPRate, p.config.ICMPBurst)
		}
	}

	// 2. Sync Whitelist (Full Sync)
	currentWhitelist := make(map[string]uint16)

	// Helper to parse whitelist entries from BPF
	parseWhitelist := func(isIPv6 bool) {
		ips, err := manager.ListWhitelist(isIPv6)
		if err != nil {
			log.Printf("⚠️ [BasePlugin] Failed to list whitelist (v6=%v): %v", isIPv6, err)
			return
		}
		for _, entry := range ips {
			// entry format: "1.2.3.4/32" or "1.2.3.4/32 (port: 80)"
			parts := strings.Split(entry, " (port: ")
			cidr := parts[0]
			var port uint16 = 0
			if len(parts) > 1 {
				var portVal int
				fmt.Sscanf(strings.TrimSuffix(parts[1], ")"), "%d", &portVal)
				port = uint16(portVal)
			}
			currentWhitelist[cidr] = port
		}
	}
	parseWhitelist(false)
	parseWhitelist(true)

	desiredWhitelist := make(map[string]uint16)
	for _, entry := range p.config.Whitelist {
		cidr := entry
		var port uint16

		// Parse port from config entry using helper (handles IP:Port, [IPv6]:Port, CIDR:Port)
		// 使用辅助函数从配置条目解析端口（处理 IP:Port, [IPv6]:Port, CIDR:Port）
		host, pVal, err := iputil.ParseIPPort(entry)
		if err == nil {
			cidr = host
			port = pVal
		}

		// Normalize CIDR
		normKey := iputil.NormalizeCIDR(cidr)
		if iputil.IsValidCIDR(normKey) {
			desiredWhitelist[normKey] = port
		}
	}

	// Remove obsolete
	for cidr := range currentWhitelist {
		if _, ok := desiredWhitelist[cidr]; !ok {
			if err := manager.RemoveAllowStatic(cidr); err != nil {
				log.Printf("⚠️ [BasePlugin] Failed to remove whitelist %s: %v", cidr, err)
			} else {
				log.Printf("➖ [BasePlugin] Removed whitelist %s", cidr)
			}
		} else {
			// Check if port changed
			if currentWhitelist[cidr] != desiredWhitelist[cidr] {
				// AllowStatic overwrites, so just log
				log.Printf("🔄 [BasePlugin] Updating whitelist %s port %d -> %d", cidr, currentWhitelist[cidr], desiredWhitelist[cidr])
			}
		}
	}

	// Add new or update
	for cidr, port := range desiredWhitelist {
		// Always apply to ensure port is correct and map is consistent
		if err := manager.AllowStatic(cidr, port); err != nil {
			log.Printf("⚠️ [BasePlugin] Failed to allow %s: %v", cidr, err)
		} else {
			if _, ok := currentWhitelist[cidr]; !ok {
				log.Printf("➕ [BasePlugin] Added whitelist %s (port: %d)", cidr, port)
			}
		}
	}

	// 3. Apply lock list from binary compressed file (Preferred)
	if p.config.LockListBinary != "" {
		if _, err := os.Stat(p.config.LockListBinary); err == nil {
			count, err := p.loadBinaryRules(manager)
			if err == nil {
				log.Printf("🛡️  [BasePlugin] Pre-loaded %d rules from binary %s", count, p.config.LockListBinary)
				return nil // Skip text file if binary loading succeeded
			}
			log.Printf("⚠️  [BasePlugin] Failed to load binary rules: %v, falling back to text file", err)
		}
	}

	// 4. Apply lock list from text file (Fallback)
	if p.config.LockListFile != "" {
		if _, err := os.Stat(p.config.LockListFile); err == nil {
			file, err := os.Open(p.config.LockListFile)
			if err == nil {
				var lines []string
				scanner := bufio.NewScanner(file)
				for scanner.Scan() {
					line := strings.TrimSpace(scanner.Text())
					if line != "" && !strings.HasPrefix(line, "#") {
						lines = append(lines, line)
					}
				}
				file.Close()

				merged, err := ipmerge.MergeCIDRs(lines)
				if err != nil {
					log.Printf("⚠️  [BasePlugin] Merge error: %v", err)
					merged = lines
				} else {
					log.Printf("ℹ️  [BasePlugin] Optimized locklist from %d to %d rules", len(lines), len(merged))
				}

				count := 0
				for _, line := range merged {
					if err := manager.BlockStatic(line, ""); err != nil {
						log.Printf("⚠️  [BasePlugin] Failed to block %s: %v", line, err)
					}
					count++
				}
				log.Printf("🛡️  [BasePlugin] Pre-loaded %d IPs/ranges from %s", count, p.config.LockListFile)
			}
		}
	}

	log.Printf("✅ [BasePlugin] Applied default_deny=%v and %d whitelist entries",
		p.config.DefaultDeny, len(desiredWhitelist))
	return nil
}

func (p *BasePlugin) loadBinaryRules(manager *xdp.Manager) (int, error) {
	// 1. Decompress to temporary file
	tmpBin := p.config.LockListBinary + ".decomp"
	cmd := exec.Command("zstd", "-d", "-f", "-o", tmpBin, p.config.LockListBinary)
	if output, err := cmd.CombinedOutput(); err != nil {
		return 0, fmt.Errorf("zstd decompression failed: %v, output: %s", err, string(output))
	}
	defer os.Remove(tmpBin)

	// 2. Open and mmap the temporary file
	file, err := os.Open(tmpBin)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return 0, err
	}

	if info.Size() == 0 {
		return 0, nil
	}

	data, err := syscall.Mmap(int(file.Fd()), 0, int(info.Size()), syscall.PROT_READ, syscall.MAP_SHARED)
	if err != nil {
		return 0, fmt.Errorf("mmap failed: %v", err)
	}
	defer syscall.Munmap(data)

	// 3. Decode from mmaped data
	// Since binary.Decode takes an io.Reader, we can use a bytes.Reader
	reader := bytes.NewReader(data)
	records, err := nxfwbin.Decode(reader)
	if err != nil {
		return 0, err
	}

	// 4. Load into BPF maps
	count := 0
	for _, r := range records {
		if err := manager.BlockStatic(fmt.Sprintf("%s/%d", r.IP.String(), r.PrefixLen), ""); err != nil {
			continue
		}
		count++
	}

	return count, nil
}

func (p *BasePlugin) Stop() error {
	return nil
}

func (p *BasePlugin) DefaultConfig() interface{} {
	dir := filepath.Dir(config.GetConfigPath())
	return types.BaseConfig{
		DefaultDeny:            true,
		AllowReturnTraffic:     false,
		AllowICMP:              true,
		EnableAFXDP:            false,
		StrictProtocol:         false,
		DropFragments:          false,
		StrictTCP:              false,
		SYNLimit:               false,
		ICMPRate:               10,
		ICMPBurst:              50,
		Whitelist:              []string{"127.0.0.1/32"},
		LockListFile:           filepath.Join(dir, "rules.deny.txt"),
		LockListBinary:         filepath.Join(dir, "rules.deny.bin.zst"),
		LockListMergeThreshold: 0,
		EnableExpiry:           false,
		CleanupInterval:        "1m",
		PersistRules:           true,
	}
}

func (p *BasePlugin) Validate(config *types.GlobalConfig) error {
	if config.Base.EnableExpiry {
		if _, err := time.ParseDuration(config.Base.CleanupInterval); err != nil {
			return fmt.Errorf("invalid cleanup_interval: %v", err)
		}
	}
	return nil
}
