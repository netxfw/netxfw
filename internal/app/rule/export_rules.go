package rule

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/netxfw/netxfw/internal/binary"
	sdk "github.com/netxfw/netxfw/pkg/sdk"
)

func ExportStructured(w io.Writer, gateway ConfigGateway, fw *sdk.SDK, filePath, format string) error {
	exportData, err := collectExportData(fw)
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

	if err := gateway.WriteFile(filePath, data, 0600, "app.rule.ExportStructured"); err != nil {
		return err
	}

	_, _ = fmt.Fprintf(w, "[OK] Exported %d rules to %s (format: %s)\n", len(exportData.Blacklist)+len(exportData.Whitelist)+len(exportData.IPPort), filePath, format)
	return nil
}

func ExportCSV(w io.Writer, gateway ConfigGateway, fw *sdk.SDK, filePath string) error {
	exportData, err := collectExportData(fw)
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

	if err := gateway.WriteFile(filePath, []byte(buf.String()), 0600, "app.rule.ExportCSV"); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(w, "[OK] Exported rules to %s (format: csv)\n", filePath)
	return nil
}

func ExportBinary(w io.Writer, fw *sdk.SDK, filePath string) error {
	blacklist, _, err := fw.Blacklist.List(100000, "")
	if err != nil {
		return err
	}

	records := make([]binary.Record, 0, len(blacklist))
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
		records = append(records, binary.Record{IP: ip, PrefixLen: prefixLen, IsIPv6: ip.To4() == nil})
	}

	tmpFile, err := os.CreateTemp("", "netxfw-binary-*.bin")
	if err != nil {
		return err
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if err := binary.Encode(tmpFile, records); err != nil {
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

func collectExportData(fw *sdk.SDK) (ExportData, error) {
	exportData := ExportData{}

	blacklist, _, err := fw.Blacklist.List(100000, "")
	if err != nil {
		return exportData, fmt.Errorf("failed to get blacklist: %w", err)
	}
	for _, entry := range blacklist {
		exportData.Blacklist = append(exportData.Blacklist, ExportRule{Type: "blacklist", IP: entry.IP})
	}

	whitelist, _, err := fw.Whitelist.List(100000, "")
	if err != nil {
		return exportData, fmt.Errorf("failed to get whitelist: %w", err)
	}
	for _, ip := range whitelist {
		exportData.Whitelist = append(exportData.Whitelist, ExportRule{Type: "whitelist", IP: ip})
	}

	ipportRules, _, err := fw.Rule.ListIPPortRules(100000, "")
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
