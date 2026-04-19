package config

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/netxfw/netxfw/internal/adapters/configfile"
	domainconfig "github.com/netxfw/netxfw/internal/domain/config"
	"github.com/netxfw/netxfw/internal/ports"
	"github.com/netxfw/netxfw/internal/utils/fileutil"
)

type WriteGateway interface {
	ports.FileWriter
	ports.ConfigWriter
}

type atomicWriteGateway struct {
	mu sync.Mutex
}

var defaultWriteGateway WriteGateway = &atomicWriteGateway{}

func DefaultWriteGateway() WriteGateway {
	return defaultWriteGateway
}

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

func (g *atomicWriteGateway) SaveConfig(path string, cfg *domainconfig.Config, keepBackups int, source string) error {
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
