package rule

// ExportRule represents a single rule for structured import/export.
type ExportRule struct {
	Type   string `json:"type" toml:"type"`
	IP     string `json:"ip" toml:"ip"`
	Port   int    `json:"port,omitempty" toml:"port,omitempty"`
	Action string `json:"action,omitempty" toml:"action,omitempty"`
}

// ExportData represents the complete export structure.
type ExportData struct {
	Blacklist []ExportRule `json:"blacklist" toml:"blacklist"`
	Whitelist []ExportRule `json:"whitelist" toml:"whitelist"`
	IPPort    []ExportRule `json:"ipport_rules" toml:"ipport_rules"`
}
