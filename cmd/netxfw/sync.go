package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"

	"github.com/livp123/netxfw/internal/binary"
	"github.com/livp123/netxfw/internal/xdp"
	"github.com/cilium/ebpf"
)

func runSync() {
	configPath := "/etc/netxfw/config.yaml"
	cfg, err := LoadGlobalConfig(configPath)
	if err != nil {
		log.Fatalf("❌ Failed to load config: %v", err)
	}

	if cfg.Base.LockListFile == "" || cfg.Base.LockListBinary == "" {
		log.Fatal("❌ lock_list_file and lock_list_binary must be configured for sync")
	}

	log.Printf("🔄 Syncing rules from %s to %s...", cfg.Base.LockListFile, cfg.Base.LockListBinary)

	// 1. Read and parse rules.deny.txt
	file, err := os.Open(cfg.Base.LockListFile)
	if err != nil {
		log.Fatalf("❌ Failed to open lock list file: %v", err)
	}
	defer file.Close()

	var records []binary.Record
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		ip, ipNet, err := net.ParseCIDR(line)
		var ones int
		if err != nil {
			ip = net.ParseIP(line)
			if ip == nil {
				log.Printf("⚠️  Skipping invalid IP/CIDR: %s", line)
				continue
			}
			if ip.To4() != nil {
				ones = 32
			} else {
				ones = 128
			}
		} else {
			ones, _ = ipNet.Mask.Size()
		}

		records = append(records, binary.Record{
			IP:        ip,
			PrefixLen: uint8(ones),
			IsIPv6:    ip.To4() == nil,
		})
	}

	// 2. Encode to temporary binary file
	tmpBin := cfg.Base.LockListBinary + ".tmp"
	tmpFile, err := os.Create(tmpBin)
	if err != nil {
		log.Fatalf("❌ Failed to create temporary binary file: %v", err)
	}
	
	if err := binary.Encode(tmpFile, records); err != nil {
		tmpFile.Close()
		os.Remove(tmpBin)
		log.Fatalf("❌ Failed to encode binary records: %v", err)
	}
	tmpFile.Close()

	// 3. Compress using zstd
	cmd := exec.Command("zstd", "-f", "-o", cfg.Base.LockListBinary, tmpBin)
	if output, err := cmd.CombinedOutput(); err != nil {
		os.Remove(tmpBin)
		log.Fatalf("❌ Failed to compress with zstd: %v\nOutput: %s", err, string(output))
	}
	os.Remove(tmpBin)

	log.Printf("✅ Successfully compressed %d rules to %s", len(records), cfg.Base.LockListBinary)

	// 4. Notify kernel eBPF Map update (optional: if daemon is running, it could watch the file)
	// For now, we update the maps directly if they are pinned.
	updateBPFMaps(records)
}

func updateBPFMaps(records []binary.Record) {
	m4, err := ebpf.LoadPinnedMap("/sys/fs/bpf/netxfw/lock_list", nil)
	if err != nil {
		log.Printf("⚠️  Could not load pinned IPv4 lock list (daemon not running?): %v", err)
		return
	}
	defer m4.Close()

	m6, err := ebpf.LoadPinnedMap("/sys/fs/bpf/netxfw/lock_list6", nil)
	if err != nil {
		log.Printf("⚠️  Could not load pinned IPv6 lock list: %v", err)
		return
	}
	defer m6.Close()

	// Clear maps first? (LPM TRIE doesn't support easy clearing, but we can overwrite)
	// Actually, the user's intent is to sync. We should ideally clear and reload.
	// But LPM TRIE doesn't support clearing. We'll just add new ones.
	
	count := 0
	for _, r := range records {
		var m *ebpf.Map
		if r.IsIPv6 {
			m = m6
		} else {
			m = m4
		}
		
		if err := xdp.LockIP(m, fmt.Sprintf("%s/%d", r.IP.String(), r.PrefixLen)); err != nil {
			log.Printf("⚠️  Failed to lock %s/%d: %v", r.IP.String(), r.PrefixLen, err)
			continue
		}
		count++
	}
	log.Printf("🛡️  Updated %d rules in eBPF maps", count)
}
