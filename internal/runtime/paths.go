// Package runtime provides runtime functionality.
package runtime

const (
	// DefaultConfigPath is the standard location for the netxfw configuration file.
	DefaultConfigPath = "/etc/netxfw/config.toml"

	// YAMLConfigPath is the YAML config path kept for older installs.
	YAMLConfigPath = "/etc/netxfw/config.yaml"

	// DefaultPidPath is the location of the daemon PID file.
	DefaultPidPath = "/var/run/netxfw.pid"

	// InterfacePidPathPattern is the pattern for interface-specific PID files.
	InterfacePidPathPattern = "/var/run/netxfw_%s.pid"

	// BPFPinPath is the filesystem path where BPF maps and programs are pinned.
	BPFPinPath = "/sys/fs/bpf/netxfw"
)

// GetPinPath returns the active BPF pin path.
func GetPinPath() string {
	return BPFPinPath
}
