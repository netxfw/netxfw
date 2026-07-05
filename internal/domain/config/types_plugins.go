package config

import sdk "github.com/netxfw/netxfw/pkg/sdk"

// Re-export constants for backward compatibility with domain-level callers.
const (
	BPFPluginSlotStart = sdk.BPFPluginSlotStart
	BPFPluginSlotEnd   = sdk.BPFPluginSlotEnd
)

// Type aliases for SDK types — single source of truth, no conversion needed.
type BPFPluginConfig = sdk.BPFPluginConfig
type BPFPluginSettings = sdk.BPFPluginSettings
