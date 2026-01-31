package base

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	nxfwbin "github.com/livp123/netxfw/internal/binary"
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
	for _, entry := range p.config.Whitelist {
		cidr := entry
		var port uint16
		// Check if it's in IP:PORT or CIDR:PORT format
		// Handle IPv6 carefully as it contains colons
		if strings.Contains(entry, "/") {
			// CIDR format: 1.2.3.4/24:80 or 2001::/64:80
			lastColon := strings.LastIndex(entry, ":")
			if lastColon > strings.LastIndex(entry, "/") {
				// There is a colon after the slash, likely a port
				portStr := entry[lastColon+1:]
				cidr = entry[:lastColon]
				var pVal uint64
				fmt.Sscanf(portStr, "%d", &pVal)
				port = uint16(pVal)
			}
		} else if !isIPv6(entry) && strings.Contains(entry, ":") {
			// IPv4 with port: 1.2.3.4:80
			parts := strings.Split(entry, ":")
			if len(parts) == 2 {
				cidr = parts[0]
				var pVal uint64
				fmt.Sscanf(parts[1], "%d", &pVal)
				port = uint16(pVal)
			}
		}

		if isIPv6(cidr) {
			xdp.AllowIP(manager.Whitelist6(), cidr, port)
		} else {
			xdp.AllowIP(manager.Whitelist(), cidr, port)
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
		var m *ebpf.Map
		if r.IsIPv6 {
			m = manager.LockList6()
		} else {
			m = manager.LockList()
		}
		if err := xdp.LockIP(m, fmt.Sprintf("%s/%d", r.IP.String(), r.PrefixLen)); err != nil {
			continue
		}
		count++
	}

	return count, nil
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
		DefaultDeny:     false,
		Whitelist:       []string{"127.0.0.1/32"},
		LockListFile:    "/etc/netxfw/rules.deny.txt",
		LockListBinary:  "/etc/netxfw/rules.deny.bin.zst",
		EnableExpiry:    false,
		CleanupInterval: "1m",
		PersistRules:    true,
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
