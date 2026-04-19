package xdp

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/klauspost/compress/zstd"
	"github.com/netxfw/netxfw/internal/binary"
	"github.com/netxfw/netxfw/pkg/sdk"
)

// loadFromBinaryFile loads rules directly from the binary cache file.
func (m *Manager) loadFromBinaryFile(cfg *sdk.GlobalConfig) error {
	file, err := os.Open(cfg.Base.LockListBinary)
	if err != nil {
		return fmt.Errorf("failed to open binary file: %v", err)
	}
	defer file.Close()

	decoder, err := zstd.NewReader(file)
	if err != nil {
		return fmt.Errorf("failed to create zstd decoder: %v", err)
	}
	defer decoder.Close()

	records, err := binary.Decode(decoder)
	if err != nil {
		return fmt.Errorf("failed to decode binary records: %v", err)
	}

	m.syncBlacklistRecords(records)
	m.logger.Infof("[OK] Loaded %d rules from binary file", len(records))
	return nil
}

// UpdateBinaryCache encodes records to binary format and compresses them.
func (m *Manager) UpdateBinaryCache(cfg *sdk.GlobalConfig, records []binary.Record) {
	if cfg.Base.LockListBinary == "" {
		return
	}

	lockListBinary := filepath.Clean(cfg.Base.LockListBinary)
	if strings.ContainsAny(lockListBinary, ";&|`$()") {
		m.logger.Errorf("[ERROR] Invalid characters in lock_list_binary path")
		return
	}

	tmpBin := lockListBinary + ".tmp"
	safeTmpBin := filepath.Clean(tmpBin)
	tmpFile, createErr := os.Create(safeTmpBin) // #nosec G304 // path sanitized above
	if createErr != nil {
		m.logger.Errorf("[ERROR] Failed to create staging binary file: %v", createErr)
		return
	}

	if encodeErr := binary.Encode(tmpFile, records); encodeErr != nil {
		tmpFile.Close()
		_ = os.Remove(tmpBin)
		m.logger.Errorf("[ERROR] Failed to encode binary records: %v", encodeErr)
		return
	}
	_ = tmpFile.Close()

	absLockListBinary, err := filepath.Abs(lockListBinary)
	if err != nil {
		_ = os.Remove(tmpBin)
		m.logger.Errorf("[ERROR] Failed to get absolute path: %v", err)
		return
	}
	absTmpBin, err := filepath.Abs(tmpBin)
	if err != nil {
		_ = os.Remove(tmpBin)
		m.logger.Errorf("[ERROR] Failed to get absolute path: %v", err)
		return
	}

	cmd := exec.Command("zstd", "-f", "-o", absLockListBinary, absTmpBin) // #nosec G204 // validated paths
	if output, err := cmd.CombinedOutput(); err != nil {
		_ = os.Remove(tmpBin)
		m.logger.Errorf("[ERROR] Failed to compress with zstd: %v\nOutput: %s", err, string(output))
		return
	}
	_ = os.Remove(tmpBin)
	m.logger.Infof("[OK] Successfully updated binary cache %s", lockListBinary)
}
