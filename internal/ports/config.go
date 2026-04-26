// Package ports provides ports functionality.
package ports

import (
	"os"

	domainconfig "github.com/netxfw/netxfw/internal/domain/config"
)

// ConfigRepository exposes config persistence behind the app boundary.
type ConfigRepository interface {
	Load() (*domainconfig.Config, error)
	Save(*domainconfig.Config) error
	SaveWithBackup(*domainconfig.Config, int) error
}

// ConfigMutator exposes the common load-mutate-save flow.
type ConfigMutator interface {
	MutateLoaded(func(*domainconfig.Config) error) error
}

// FileWriter captures atomic file write behavior used by app services.
type FileWriter interface {
	WriteFile(path string, data []byte, perm os.FileMode, source string) error
}

// ConfigWriter captures config persistence behavior used by app services.
type ConfigWriter interface {
	SaveConfig(path string, cfg *domainconfig.Config, keepBackups int, source string) error
}
