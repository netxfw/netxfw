package app

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/klauspost/compress/zstd"
	"github.com/netxfw/netxfw/internal/config"
	"github.com/netxfw/netxfw/pkg/sdk"
)

func validateIP(ip string) error {
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP: %s", ip)
	}
	return nil
}

func validateImportFile(filePath string) (string, error) {
	if filePath == "" {
		return "", fmt.Errorf("empty path")
	}
	abs, err := filepath.Abs(filePath)
	if err != nil {
		return "", err
	}
	return abs, nil
}

func CollectExportData(s *sdk.SDK) (ExportData, error) {
	exportData := ExportData{}

	blacklist, _, err := s.Blacklist.List(100000, "")
	if err != nil {
		return exportData, fmt.Errorf("failed to get blacklist: %w", err)
	}
	for _, entry := range blacklist {
		exportData.Blacklist = append(exportData.Blacklist, ExportRule{Type: "blacklist", IP: entry.IP})
	}

	whitelist, _, err := s.Whitelist.List(100000, "")
	if err != nil {
		return exportData, fmt.Errorf("failed to get whitelist: %w", err)
	}
	for _, ip := range whitelist {
		exportData.Whitelist = append(exportData.Whitelist, ExportRule{Type: "whitelist", IP: ip})
	}

	ipportRules, _, err := s.Rule.ListIPPortRules(100000, "")
	if err != nil {
		return exportData, fmt.Errorf("failed to get IP+Port rules: %w", err)
	}
	for _, rule := range ipportRules {
		action := "deny"
		if rule.Action == 1 {
			action = "allow"
		}
		exportData.IPPort = append(exportData.IPPort, ExportRule{
			Type:   "ipport",
			IP:     rule.IP,
			Port:   int(rule.Port),
			Action: action,
		})
	}

	return exportData, nil
}

func parseImportFile(filePath string, isJSON bool) (*ExportData, error) {
	safePath, err := validateImportFile(filePath)
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

type importResult struct {
	added  int
	failed int
}

func ImportFromStructuredFile(w io.Writer, s *sdk.SDK, filePath string, isJSON bool) error {
	importData, err := parseImportFile(filePath, isJSON)
	if err != nil {
		return err
	}

	var blResult, wlResult, ippResult importResult

	for _, rule := range importData.Blacklist {
		if rule.IP == "" {
			continue
		}
		if err := validateIP(rule.IP); err != nil {
			_, _ = fmt.Fprintf(w, "[WARN]  Failed to add blacklist %s\n", rule.IP)
			blResult.failed++
		} else if err := s.Blacklist.Add(rule.IP); err != nil {
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
		if err := validateIP(rule.IP); err != nil {
			_, _ = fmt.Fprintf(w, "[WARN]  Failed to add whitelist %s\n", rule.IP)
			wlResult.failed++
		} else if err := s.Whitelist.Add(rule.IP, port); err != nil {
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
		if err := validateIP(rule.IP); err != nil {
			_, _ = fmt.Fprintf(w, "[WARN]  Failed to add IP+Port rule %s:%d\n", rule.IP, rule.Port)
			ippResult.failed++
		} else if err := s.Rule.AddIPPortRule(rule.IP, uint16(rule.Port), action); err != nil {
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

func ExportToStructuredFile(w io.Writer, s *sdk.SDK, filePath, format string) error {
	exportData, err := CollectExportData(s)
	if err != nil {
		return err
	}

	var data []byte
	if format == "toml" {
		data, err = toml.Marshal(exportData)
	} else {
		data, err = json.MarshalIndent(exportData, "", "  ")
	}
	if err != nil {
		return err
	}

	if err := config.DefaultWriteGateway().WriteFile(filePath, data, 0600, "app.rule_io.ExportToStructuredFile"); err != nil {
		return err
	}

	_, _ = fmt.Fprintf(w, "[OK] Exported %d rules to %s (format: %s)\n", len(exportData.Blacklist)+len(exportData.Whitelist)+len(exportData.IPPort), filePath, format)
	return nil
}

func ExportToCSVFile(w io.Writer, s *sdk.SDK, filePath string) error {
	exportData, err := CollectExportData(s)
	if err != nil {
		return err
	}

	var buf strings.Builder
	writer := csv.NewWriter(&buf)
	if err := writer.Write([]string{"type", "ip", "port", "action"}); err != nil {
		return err
	}
	for _, rule := range exportData.Blacklist {
		if err := writer.Write([]string{rule.Type, rule.IP, "", ""}); err != nil {
			return err
		}
	}
	for _, rule := range exportData.Whitelist {
		if err := writer.Write([]string{rule.Type, rule.IP, "", ""}); err != nil {
			return err
		}
	}
	for _, rule := range exportData.IPPort {
		if err := writer.Write([]string{rule.Type, rule.IP, strconv.Itoa(rule.Port), rule.Action}); err != nil {
			return err
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return err
	}

	if err := config.DefaultWriteGateway().WriteFile(filePath, []byte(buf.String()), 0600, "app.rule_io.ExportToCSVFile"); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(w, "[OK] Exported rules to %s (format: csv)\n", filePath)
	return nil
}

func ImportFromBinaryFile(w io.Writer, s *sdk.SDK, filePath string) error {
	safePath, err := validateImportFile(filePath)
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

	records, err := DecodeBinaryRecords(decoder)
	if err != nil {
		return err
	}

	var added, failed int
	for _, record := range records {
		ipStr := fmt.Sprintf("%s/%d", record.IP.String(), record.PrefixLen)
		if err := s.Blacklist.Add(ipStr); err != nil {
			failed++
		} else {
			added++
		}
	}
	_, _ = fmt.Fprintf(w, "[OK] Binary import completed:\n   Blacklist: %d added, %d failed\n", added, failed)
	return nil
}

func ExportToBinaryFile(w io.Writer, s *sdk.SDK, filePath string) error {
	blacklist, _, err := s.Blacklist.List(100000, "")
	if err != nil {
		return err
	}

	records := make([]BinaryRecord, 0, len(blacklist))
	for _, entry := range blacklist {
		var ip net.IP
		var prefixLen uint8
		if strings.Contains(entry.IP, "/") {
			ipStr, cidrNet, _ := net.ParseCIDR(entry.IP)
			ip = ipStr
			ones, _ := cidrNet.Mask.Size()
			prefixLen = uint8(ones)
		} else {
			ip = net.ParseIP(entry.IP)
			if ip.To4() != nil {
				prefixLen = 32
			} else {
				prefixLen = 128
			}
		}
		records = append(records, BinaryRecord{IP: ip, PrefixLen: prefixLen, IsIPv6: ip.To4() == nil})
	}

	tmpFile, err := os.CreateTemp("", "netxfw-binary-*.bin")
	if err != nil {
		return err
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if err := EncodeBinaryRecords(tmpFile, records); err != nil {
		tmpFile.Close()
		return err
	}
	tmpFile.Close()

	zstdCmd := exec.Command("zstd", "-f", "-o", filePath, tmpPath)
	if _, err := zstdCmd.CombinedOutput(); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(w, "[OK] Exported blacklist to %s\n", filePath)
	return nil
}
