package sdk

import (
	"fmt"
	"net"
	"strings"
)

// LoggingConfig defines the configuration for logging.
type LoggingConfig struct {
	Enabled    bool   `toml:"enabled"`
	Level      string `toml:"level"`
	Path       string `toml:"path"`
	MaxSize    int    `toml:"max_size"`
	MaxBackups int    `toml:"max_backups"`
	MaxAge     int    `toml:"max_age"`
	Compress   bool   `toml:"compress"`
}

const (
	// BPFPluginSlotStart and BPFPluginSlotEnd define the supported jump-table
	// slot range for configured datapath plugins.
	BPFPluginSlotStart = 2
	BPFPluginSlotEnd   = 14
)

// BPFPluginConfig defines the configuration for a BPF plugin.
type BPFPluginConfig struct {
	Path        string `toml:"path"`
	Index       int    `toml:"index"`
	Enabled     bool   `toml:"enabled"`
	Description string `toml:"description"`
}

// BPFPluginSettings defines global BPF plugin settings.
type BPFPluginSettings struct {
	Enabled bool              `toml:"enabled"`
	Plugins []BPFPluginConfig `toml:"plugins"`
}

// GlobalConfig represents the top-level configuration structure.
type GlobalConfig struct {
	Cluster   ClusterConfig     `toml:"cluster"`
	Base      BaseConfig        `toml:"base"`
	Web       WebConfig         `toml:"web"`
	Metrics   MetricsConfig     `toml:"metrics"`
	Port      PortConfig        `toml:"port"`
	Conntrack ConntrackConfig   `toml:"conntrack"`
	RateLimit RateLimitConfig   `toml:"rate_limit"`
	LogEngine LogEngineConfig   `toml:"log_engine"`
	Capacity  CapacityConfig    `toml:"capacity"`
	Logging   LoggingConfig     `toml:"logging"`
	Cloud     CloudConfig       `toml:"cloud"`
	AI        AIConfig          `toml:"-"`
	MCP       MCPConfig         `toml:"-"`
	BPFPlugin BPFPluginSettings `toml:"bpf_plugin"`
	Modules   []ModuleConfig    `toml:"modules"`
}

// ModuleConfig defines the configuration for a BPF module.
type ModuleConfig struct {
	Name     string `toml:"name"`
	Enabled  bool   `toml:"enabled"`
	Priority int    `toml:"priority"`
}

// LogEngineConfig defines the configuration for the log engine.
type LogEngineConfig struct {
	Enabled   bool            `toml:"enabled"`
	Workers   int             `toml:"workers"`
	MaxWindow int             `toml:"max_window"`
	Rules     []LogEngineRule `toml:"rules"`
}

// LogEngineRule defines a rule for the log engine.
type LogEngineRule struct {
	ID           string   `toml:"id"`
	Path         string   `toml:"path"`
	TailPosition string   `toml:"tail_position"`
	Expression   string   `toml:"expression"`
	Action       string   `toml:"action"`
	Keywords     []string `toml:"keywords"`
	Contains     []string `toml:"contains"`
	AnyContains  []string `toml:"any_contains"`
	NotContains  []string `toml:"not_contains"`
	And          []string `toml:"and"`
	Is           []string `toml:"is"`
	Or           []string `toml:"or"`
	Not          []string `toml:"not"`
	Regex        string   `toml:"regex"`
	Threshold    int      `toml:"threshold"`
	Interval     int      `toml:"interval"`
	TTL          string   `toml:"ttl"`
}

// RateLimitConfig defines the configuration for rate limiting.
type RateLimitConfig struct {
	Enabled         bool            `toml:"enabled"`
	AutoBlock       bool            `toml:"auto_block"`
	AutoBlockExpiry string          `toml:"auto_block_expiry"`
	Rules           []RateLimitRule `toml:"rules"`
}

// RateLimitRule defines a rate limit rule for a specific IP/CIDR.
type RateLimitRule struct {
	IP    string `toml:"ip"`
	Rate  uint64 `toml:"rate"`
	Burst uint64 `toml:"burst"`
}

// WebConfig defines the configuration for the web interface.
type WebConfig struct {
	Enabled bool   `toml:"enabled"`
	Port    int    `toml:"port"`
	Token   string `toml:"token"`
}

// AIConfig defines the configuration for AI features.
type AIConfig struct {
	Enabled bool   `toml:"-"`
	Port    int    `toml:"-"`
	Model   string `toml:"-"`
	APIKey  string `toml:"-"`
	BaseURL string `toml:"-"`
}

// MCPConfig defines the configuration for Model Context Protocol.
type MCPConfig struct {
	Enabled bool   `toml:"-"`
	Port    int    `toml:"-"`
	Mode    string `toml:"-"`
}

// CloudConfig defines the configuration for cloud environment support.
type CloudConfig struct {
	Enabled       bool                `toml:"enabled"`
	Provider      string              `toml:"provider"`
	ProxyProtocol ProxyProtocolConfig `toml:"proxy_protocol"`
}

// ProxyProtocolConfig defines the Proxy Protocol configuration.
type ProxyProtocolConfig struct {
	Enabled         bool     `toml:"enabled"`
	TrustedLBRanges []string `toml:"trusted_lb_ranges"`
	CacheTTL        string   `toml:"cache_ttl"`
}

// ClusterConfig defines the configuration for clustering.
type ClusterConfig struct {
	Enabled    bool   `toml:"enabled"`
	ConfigPath string `toml:"configpath"`
}

// CapacityConfig defines the capacity settings for BPF maps.
type CapacityConfig struct {
	Conntrack       int `toml:"-"`
	LockList        int `toml:"lock_list"`
	DynLockList     int `toml:"dyn_lock_list"`
	Whitelist       int `toml:"whitelist"`
	IPPortRules     int `toml:"ip_port_rules"`
	AllowedPorts    int `toml:"allowed_ports"`
	RateLimits      int `toml:"rate_limits"`
	DropReasonStats int `toml:"drop_reason_stats"`
	PassReasonStats int `toml:"pass_reason_stats"`
}

// BaseConfig defines the base firewall settings.
type BaseConfig struct {
	DefaultDeny            bool     `toml:"default_deny"`
	AllowReturnTraffic     bool     `toml:"allow_return_traffic"`
	AllowICMP              bool     `toml:"allow_icmp"`
	Interfaces             []string `toml:"interfaces"`
	EnableAFXDP            bool     `toml:"enable_af_xdp"`
	StrictProtocol         bool     `toml:"strict_protocol"`
	DropFragments          bool     `toml:"drop_fragments"`
	StrictTCP              bool     `toml:"strict_tcp"`
	SYNLimit               bool     `toml:"syn_limit"`
	BogonFilter            bool     `toml:"bogon_filter"`
	ICMPRate               uint64   `toml:"icmp_rate"`
	ICMPBurst              uint64   `toml:"icmp_burst"`
	Whitelist              []string `toml:"whitelist"`
	LockListFile           string   `toml:"lock_list_file"`
	LockListBinary         string   `toml:"lock_list_binary"`
	LockListMergeThreshold int      `toml:"lock_list_merge_threshold"`
	LockListV4Mask         int      `toml:"lock_list_v4_mask"`
	LockListV6Mask         int      `toml:"lock_list_v6_mask"`
	BPFPinPath             string   `toml:"bpf_pin_path"`
	EnableExpiry           bool     `toml:"enable_expiry"`
	CleanupInterval        string   `toml:"cleanup_interval"`
	PersistRules           bool     `toml:"persist_rules"`
	EnablePprof            bool     `toml:"enable_pprof"`
	PprofPort              int      `toml:"pprof_port"`
	BackupKeep             int      `toml:"backup_keep"`
}

// ConntrackConfig defines the configuration for connection tracking.
type ConntrackConfig struct {
	Enabled    bool   `toml:"enabled"`
	MaxEntries int    `toml:"max_entries"`
	TCPTimeout string `toml:"tcp_timeout"`
	UDPTimeout string `toml:"udp_timeout"`
}

// MetricsConfig defines the configuration for metrics collection.
type MetricsConfig struct {
	Enabled           bool   `toml:"enabled"`
	ServerEnabled     bool   `toml:"server_enabled"`
	Port              int    `toml:"port"`
	PushEnabled       bool   `toml:"push_enabled"`
	PushGatewayAddr   string `toml:"push_gateway_addr"`
	PushInterval      string `toml:"push_interval"`
	TextfileEnabled   bool   `toml:"textfile_enabled"`
	TextfilePath      string `toml:"textfile_path"`
	TopN              int    `toml:"top_n"`
	ThresholdCritical int    `toml:"threshold_critical"`
	ThresholdHigh     int    `toml:"threshold_high"`
	ThresholdMedium   int    `toml:"threshold_medium"`
	StatsInterval     string `toml:"stats_interval"`
	AvgPacketSize     int    `toml:"avg_packet_size"`
}

// PortConfig defines the configuration for port filtering.
type PortConfig struct {
	AllowedPorts []uint16     `toml:"allowed_ports"`
	IPPortRules  []IPPortRule `toml:"ip_port_rules"`
}

func (c *BPFPluginConfig) Validate() error {
	if c.Path == "" {
		return fmt.Errorf("plugin path is required")
	}
	if c.Index < BPFPluginSlotStart || c.Index > BPFPluginSlotEnd {
		return fmt.Errorf("invalid index: %d (must be between %d and %d)", c.Index, BPFPluginSlotStart, BPFPluginSlotEnd)
	}
	return nil
}

func (c *BPFPluginSettings) Validate() error {
	if !c.Enabled {
		return nil
	}

	seen := make(map[int]int, len(c.Plugins))
	for i := range c.Plugins {
		plugin := &c.Plugins[i]
		if !plugin.Enabled {
			continue
		}
		if err := plugin.Validate(); err != nil {
			return fmt.Errorf("bpf plugin #%d: %w", i, err)
		}
		if prev, ok := seen[plugin.Index]; ok {
			return fmt.Errorf("bpf plugin #%d: duplicate index %d already used by plugin #%d", i, plugin.Index, prev)
		}
		seen[plugin.Index] = i
	}

	return nil
}

// Validate checks the configuration for errors.
func (c *GlobalConfig) Validate() error {
	if err := c.Base.Validate(); err != nil {
		return fmt.Errorf("base config error: %w", err)
	}
	if err := c.Port.Validate(); err != nil {
		return fmt.Errorf("port config error: %w", err)
	}
	if err := c.RateLimit.Validate(); err != nil {
		return fmt.Errorf("rate_limit config error: %w", err)
	}
	if err := c.LogEngine.Validate(); err != nil {
		return fmt.Errorf("log_engine config error: %w", err)
	}
	if err := c.BPFPlugin.Validate(); err != nil {
		return fmt.Errorf("bpf_plugin config error: %w", err)
	}
	if c.Conntrack.MaxEntries > 0 {
		c.Capacity.Conntrack = c.Conntrack.MaxEntries
	}
	return nil
}

func (c *BaseConfig) Validate() error {
	if c.LockListV4Mask < 0 || c.LockListV4Mask > 32 {
		return fmt.Errorf("invalid lock_list_v4_mask: %d (must be 0-32)", c.LockListV4Mask)
	}
	if c.LockListV6Mask < 0 || c.LockListV6Mask > 128 {
		return fmt.Errorf("invalid lock_list_v6_mask: %d (must be 0-128)", c.LockListV6Mask)
	}
	for i, cidr := range c.Whitelist {
		if err := validateCIDROrIP(cidr); err != nil {
			return fmt.Errorf("invalid whitelist entry #%d (%s): %w", i, cidr, err)
		}
	}
	return nil
}

func (c *PortConfig) Validate() error {
	for i, rule := range c.IPPortRules {
		if rule.Port == 0 {
			return fmt.Errorf("invalid ip_port_rule #%d: port cannot be 0", i)
		}
		if rule.Action != 0 && rule.Action != 1 && rule.Action != 2 {
			return fmt.Errorf("invalid ip_port_rule #%d: action must be 0/2 (deny) or 1 (allow)", i)
		}
		if err := validateCIDROrIP(rule.IP); err != nil {
			return fmt.Errorf("invalid ip_port_rule #%d IP (%s): %w", i, rule.IP, err)
		}
	}
	return nil
}

func (c *RateLimitConfig) Validate() error {
	for i, rule := range c.Rules {
		if err := validateCIDROrIP(rule.IP); err != nil {
			return fmt.Errorf("invalid rate_limit rule #%d IP (%s): %w", i, rule.IP, err)
		}
	}
	return nil
}

func (c *LogEngineConfig) Validate() error {
	for i := range c.Rules {
		rule := &c.Rules[i]
		if rule.TailPosition != "" && rule.TailPosition != "start" && rule.TailPosition != "end" && rule.TailPosition != "offset" {
			return fmt.Errorf("invalid log_engine rule #%d: invalid tail_position '%s'", i, rule.TailPosition)
		}
		if rule.Action == "" {
			continue
		}
		switch rule.Action {
		case "0", "1", "2", "log", "block", "dynamic", "static", "permanent", "lock", "deny", "black", "dynblock", "dynblack":
			continue
		}
		if !strings.HasPrefix(rule.Action, "block:") && !strings.HasPrefix(rule.Action, "black:") {
			return fmt.Errorf("invalid log_engine rule #%d: invalid action '%s'", i, rule.Action)
		}
	}
	return nil
}

func validateCIDROrIP(s string) error {
	if _, _, err := net.ParseCIDR(s); err == nil {
		return nil
	}
	if ip := net.ParseIP(s); ip != nil {
		return nil
	}
	host, _, err := net.SplitHostPort(s)
	if err == nil {
		if _, _, cidrErr := net.ParseCIDR(host); cidrErr == nil {
			return nil
		}
		if ip := net.ParseIP(host); ip != nil {
			return nil
		}
	}
	return fmt.Errorf("invalid CIDR or IP format")
}

// ValidateCIDROrIPForConfig validates config CIDR/IP fields, including host:port forms.
func ValidateCIDROrIPForConfig(s string) error {
	return validateCIDROrIP(s)
}
