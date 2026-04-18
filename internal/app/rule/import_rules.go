package rule

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/klauspost/compress/zstd"
	"github.com/netxfw/netxfw/internal/binary"
	"github.com/netxfw/netxfw/internal/config"
	domainrule "github.com/netxfw/netxfw/internal/domain/rule"
	"github.com/netxfw/netxfw/pkg/sdk"
)

type importResult struct {
	added  int
	failed int
}

func ImportText(w io.Writer, fw *sdk.SDK, ruleType string, filePath string) error {
	safePath, err := validateImportPath(filePath)
	if err != nil {
		return err
	}

	file, err := os.Open(safePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	switch ruleType {
	case "lock", "deny":
		return importLockList(w, fw, file)
	case "allow":
		return importWhitelist(w, fw, file)
	case "rules":
		return importIPPortRules(w, fw, file)
	default:
		return fmt.Errorf("[ERROR] Unknown rule type. Use: lock (or deny), allow, rules, binary, or all (for JSON/TOML)")
	}
}

func ImportStructured(w io.Writer, fw *sdk.SDK, filePath string, isJSON bool) error {
	importData, err := parseImportFile(filePath, isJSON)
	if err != nil {
		return err
	}

	var blResult, wlResult, ippResult importResult

	for _, rule := range importData.Blacklist {
		if rule.IP == "" {
			continue
		}
		if err := validatePlainIP(rule.IP); err != nil {
			_, _ = fmt.Fprintf(w, "[WARN]  Failed to add blacklist %s\n", rule.IP)
			blResult.failed++
		} else if err := fw.Blacklist.Add(rule.IP); err != nil {
			_, _ = fmt.Fprintf(w, "[WARN]  Failed to add blacklist %s\n", rule.IP)
			blResult.failed++
		} else {
			blResult.added++
		}
	}

	for _, rule := range importData.Whitelist {
		if rule.IP == "" {
			continue
		}
		var port uint16
		if rule.Port > 0 {
			port = uint16(rule.Port)
		}
		if err := validatePlainIP(rule.IP); err != nil {
			_, _ = fmt.Fprintf(w, "[WARN]  Failed to add whitelist %s\n", rule.IP)
			wlResult.failed++
		} else if err := fw.Whitelist.Add(rule.IP, port); err != nil {
			_, _ = fmt.Fprintf(w, "[WARN]  Failed to add whitelist %s\n", rule.IP)
			wlResult.failed++
		} else {
			wlResult.added++
		}
	}

	for _, rule := range importData.IPPort {
		if rule.IP == "" || rule.Port == 0 {
			continue
		}
		action := uint8(0)
		if rule.Action == "allow" {
			action = 1
		}
		if err := validatePlainIP(rule.IP); err != nil {
			_, _ = fmt.Fprintf(w, "[WARN]  Failed to add IP+Port rule %s:%d\n", rule.IP, rule.Port)
			ippResult.failed++
		} else if err := fw.Rule.AddIPPortRule(rule.IP, uint16(rule.Port), action); err != nil {
			_, _ = fmt.Fprintf(w, "[WARN]  Failed to add IP+Port rule %s:%d\n", rule.IP, rule.Port)
			ippResult.failed++
		} else {
			ippResult.added++
		}
	}

	_, _ = fmt.Fprintf(w, "[OK] Import completed:\n   Blacklist: %d added, %d failed\n   Whitelist: %d added, %d failed\n   IP+Port:   %d added, %d failed\n",
		blResult.added, blResult.failed, wlResult.added, wlResult.failed, ippResult.added, ippResult.failed)
	return nil
}

func ImportBinary(w io.Writer, fw *sdk.SDK, filePath string) error {
	safePath, err := validateImportPath(filePath)
	if err != nil {
		return err
	}

	file, err := os.Open(safePath)
	if err != nil {
		return err
	}
	defer file.Close()

	decoder, err := zstd.NewReader(file)
	if err != nil {
		return err
	}
	defer decoder.Close()

	records, err := binary.Decode(decoder)
	if err != nil {
		return err
	}

	var added, failed int
	for _, record := range records {
		ipStr := fmt.Sprintf("%s/%d", record.IP.String(), record.PrefixLen)
		if err := fw.Blacklist.Add(ipStr); err != nil {
			failed++
		} else {
			added++
		}
	}
	_, _ = fmt.Fprintf(w, "[OK] Binary import completed:\n   Blacklist: %d added, %d failed\n", added, failed)
	return nil
}

func validateImportPath(filePath string) (string, error) {
	if filePath == "" {
		return "", fmt.Errorf("empty path")
	}
	return filepath.Abs(filePath)
}

func parseImportFile(filePath string, isJSON bool) (*ExportData, error) {
	safePath, err := validateImportPath(filePath)
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(safePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	var importData ExportData
	if isJSON {
		if err := json.Unmarshal(data, &importData); err != nil {
			return nil, fmt.Errorf("failed to parse JSON: %w", err)
		}
	} else {
		if err := toml.Unmarshal(data, &importData); err != nil {
			return nil, fmt.Errorf("failed to parse TOML: %w", err)
		}
	}

	return &importData, nil
}

func validatePlainIP(ip string) error {
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP: %s", ip)
	}
	return nil
}

func importLockList(w io.Writer, fw *sdk.SDK, r io.Reader) error {
	persistFile := ""
	if cfg, err := config.ReloadCurrentConfig(); err == nil && cfg != nil {
		persistFile = cfg.Base.LockListFile
	}

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if err := domainrule.ValidateIP(line); err != nil {
			_, _ = fmt.Fprintf(w, "[WARN] Invalid IP format: %s: %v\n", line, err)
			continue
		}
		if persistFile != "" {
			if err := fw.Blacklist.AddWithFile(line, persistFile); err != nil {
				_, _ = fmt.Fprintf(w, "[WARN] Failed to add %s: %v\n", line, err)
			} else {
				_, _ = fmt.Fprintf(w, "[OK] Added %s to blacklist\n", line)
			}
			continue
		}
		if err := fw.Blacklist.Add(line); err != nil {
			_, _ = fmt.Fprintf(w, "[WARN] Failed to add %s: %v\n", line, err)
		} else {
			_, _ = fmt.Fprintf(w, "[OK] Added %s to blacklist\n", line)
		}
	}
	return scanner.Err()
}

func importWhitelist(w io.Writer, fw *sdk.SDK, r io.Reader) error {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		selector, err := domainrule.ParseSelector(line)
		if err != nil {
			_, _ = fmt.Fprintf(w, "[WARN] Invalid IP format: %s: %v\n", line, err)
			continue
		}
		if err := fw.Whitelist.Add(selector.CIDR, selector.Port); err != nil {
			_, _ = fmt.Fprintf(w, "[WARN] Failed to add %s: %v\n", line, err)
		} else {
			_, _ = fmt.Fprintf(w, "[OK] Added %s to whitelist\n", line)
		}
	}
	return scanner.Err()
}

func importIPPortRules(w io.Writer, fw *sdk.SDK, r io.Reader) error {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Split(line, ":")
		if len(parts) < 3 {
			_, _ = fmt.Fprintf(w, "[WARN] Invalid format: %s (expected IP:Port:Action)\n", line)
			continue
		}

		selector, err := domainrule.NewSelector(parts[0], 0)
		if err != nil {
			_, _ = fmt.Fprintf(w, "[WARN] Invalid IP format: %s: %v\n", line, err)
			continue
		}
		port, err := parsePort(parts[1])
		if err != nil {
			_, _ = fmt.Fprintf(w, "[WARN] Invalid port in %s: %v\n", line, err)
			continue
		}
		action, err := domainrule.ParseAction(strings.ToLower(parts[2]))
		if err != nil {
			_, _ = fmt.Fprintf(w, "[WARN] Failed to add rule %s: %v\n", line, err)
			continue
		}

		if err := fw.Rule.AddIPPortRule(selector.CIDR, port, uint8(action)); err != nil {
			_, _ = fmt.Fprintf(w, "[WARN] Failed to add rule %s: %v\n", line, err)
		} else {
			_, _ = fmt.Fprintf(w, "[OK] Added rule %s\n", line)
		}
	}
	return scanner.Err()
}

func parsePort(raw string) (uint16, error) {
	port, err := strconv.Atoi(raw)
	if err != nil {
		return 0, err
	}
	if err := domainrule.ValidatePort(port, true); err != nil {
		return 0, err
	}
	return uint16(port), nil
}
