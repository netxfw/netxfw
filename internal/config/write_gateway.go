package config

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/netxfw/netxfw/internal/adapters/configfile"
	"github.com/netxfw/netxfw/internal/configtypes"
	"github.com/netxfw/netxfw/internal/utils/fileutil"
)

// WriteGateway is the unified persistence entry for config and state writes.
type WriteGateway interface {
	WriteFile(path string, data []byte, perm os.FileMode, source string) error
	SaveGlobalConfig(path string, cfg *types.GlobalConfig, keepBackups int, source string) error
}

type atomicWriteGateway struct {
	mu sync.Mutex
}

var defaultWriteGateway WriteGateway = &atomicWriteGateway{}

// DefaultWriteGateway returns the process-wide write gateway.
func DefaultWriteGateway() WriteGateway {
	return defaultWriteGateway
}

// SetDefaultWriteGateway overrides the default write gateway.
func SetDefaultWriteGateway(gateway WriteGateway) {
	if gateway == nil {
		return
	}
	defaultWriteGateway = gateway
}

func (g *atomicWriteGateway) WriteFile(path string, data []byte, perm os.FileMode, source string) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	safePath := filepath.Clean(path)
	if safePath == "." || safePath == "/" {
		return fmt.Errorf("refusing to write unsafe path: %q", path)
	}
	if source == "" {
		source = "unknown"
	}
	if err := fileutil.AtomicWriteFile(safePath, data, perm); err != nil {
		return fmt.Errorf("%s write failed: %w", source, err)
	}
	return nil
}

func (g *atomicWriteGateway) SaveGlobalConfig(path string, cfg *types.GlobalConfig, keepBackups int, source string) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	safePath := filepath.Clean(path)
	if safePath == "." || safePath == "/" {
		return fmt.Errorf("refusing to save config to unsafe path: %q", path)
	}
	if source == "" {
		source = "unknown"
	}
	if err := configfile.SaveWithBackup(safePath, cfg, keepBackups); err != nil {
		return fmt.Errorf("%s config save failed: %w", source, err)
	}
	return nil
}
