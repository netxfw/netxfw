package api

import sdk "github.com/netxfw/netxfw/pkg/sdk"

type packetStats struct {
	Total   uint64 `json:"total"`
	Passed  uint64 `json:"passed"`
	Dropped uint64 `json:"dropped"`
}

type dropReasonStats struct {
	Blacklist   uint64 `json:"blacklist"`
	NoRule      uint64 `json:"no_rule"`
	Invalid     uint64 `json:"invalid"`
	RateLimit   uint64 `json:"rate_limit"`
	SynFlood    uint64 `json:"syn_flood"`
	IcmpLimit   uint64 `json:"icmp_limit"`
	PortBlocked uint64 `json:"port_blocked"`
	DefaultDeny uint64 `json:"default_deny"`
}

type passReasonStats struct {
	Whitelist   uint64 `json:"whitelist"`
	Rule        uint64 `json:"rule"`
	Return      uint64 `json:"return"`
	Established uint64 `json:"established"`
}

type statsResponse struct {
	Packets     packetStats     `json:"packets"`
	DropReasons dropReasonStats `json:"drop_reasons"`
	PassReasons passReasonStats `json:"pass_reasons"`
}

type rulesResponse struct {
	Blacklist      []sdk.BlockedIP  `json:"blacklist"`
	TotalBlacklist int              `json:"totalBlacklist"`
	Whitelist      []string         `json:"whitelist"`
	TotalWhitelist int              `json:"totalWhitelist"`
	IPPortRules    []sdk.IPPortRule `json:"ipPortRules"`
	TotalIPPort    int              `json:"totalIPPort"`
	Limit          int              `json:"limit"`
}

const (
	ruleTypeBlacklist = "blacklist"
	ruleTypeWhitelist = "whitelist"
)
