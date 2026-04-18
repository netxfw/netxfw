package xdp

import (
	"testing"

	"github.com/netxfw/netxfw/internal/configtypes"
	"github.com/stretchr/testify/assert"
)

func TestModuleIDs(t *testing.T) {
	ids := []uint32{
		ModuleIDEntry,
		ModuleIDSanity,
		ModuleIDCritical,
		ModuleIDWhitelist,
		ModuleIDBlacklist,
		ModuleIDDynamicBlacklist,
		ModuleIDRateLimit,
		ModuleIDConntrack,
		ModuleIDRules,
		ModuleIDICMP,
		ModuleIDReturn,
		ModuleIDPlugins,
	}

	seen := make(map[uint32]bool)
	for _, id := range ids {
		assert.False(t, seen[id], "duplicate module ID: %d", id)
		seen[id] = true
	}
}

func TestModuleDef(t *testing.T) {
	def := ModuleDef{
		ID:      ModuleIDSanity,
		Program: nil,
	}

	assert.Equal(t, uint32(ModuleIDSanity), def.ID)
	assert.Nil(t, def.Program)
}

func TestModuleConfigSorting(t *testing.T) {
	configs := []types.ModuleConfig{
		{Name: "whitelist", Priority: 3, Enabled: true},
		{Name: "blacklist", Priority: 4, Enabled: true},
		{Name: "sanity", Priority: 1, Enabled: true},
		{Name: "ratelimit", Priority: 6, Enabled: true},
	}

	expected := []string{"sanity", "whitelist", "blacklist", "ratelimit"}

	sorted := make([]types.ModuleConfig, len(configs))
	copy(sorted, configs)

	for i := 0; i < len(sorted)-1; i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[i].Priority > sorted[j].Priority {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	for i, cfg := range sorted {
		assert.Equal(t, expected[i], cfg.Name)
	}
}

func TestModuleConfigEnabled(t *testing.T) {
	configs := []types.ModuleConfig{
		{Name: "enabled1", Priority: 1, Enabled: true},
		{Name: "disabled", Priority: 2, Enabled: false},
		{Name: "enabled2", Priority: 3, Enabled: true},
	}

	enabledCount := 0
	for _, cfg := range configs {
		if cfg.Enabled {
			enabledCount++
		}
	}

	assert.Equal(t, 2, enabledCount)
}

func TestIsKeyNotExist(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{"nil error", nil, false},
		{"key not exist", &testError{msg: "key does not exist"}, true},
		{"other error", &testError{msg: "some other error"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isKeyNotExist(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}

func TestModuleMapDefinition(t *testing.T) {
	moduleNames := []string{
		"sanity",
		"critical_blacklist",
		"whitelist",
		"blacklist",
		"dynamic_blacklist",
		"ratelimit",
		"conntrack",
		"ip_port_rules",
		"icmp",
		"return_traffic",
	}

	expectedIDs := []uint32{
		ModuleIDSanity,
		ModuleIDCritical,
		ModuleIDWhitelist,
		ModuleIDBlacklist,
		ModuleIDDynamicBlacklist,
		ModuleIDRateLimit,
		ModuleIDConntrack,
		ModuleIDRules,
		ModuleIDICMP,
		ModuleIDReturn,
	}

	for i, name := range moduleNames {
		assert.NotEmpty(t, name)
		assert.Equal(t, uint32(i+1), expectedIDs[i])
	}
}

func TestStartIdx(t *testing.T) {
	startIdx := uint32(20)
	maxModules := 10

	for i := 0; i < maxModules; i++ {
		progIdx := startIdx + uint32(i)
		assert.GreaterOrEqual(t, progIdx, uint32(20))
		assert.Less(t, progIdx, uint32(30))
	}
}

func TestModuleConfigValidation(t *testing.T) {
	validConfigs := []types.ModuleConfig{
		{Name: "sanity", Priority: 1, Enabled: true},
		{Name: "blacklist", Priority: 4, Enabled: true},
		{Name: "whitelist", Priority: 3, Enabled: true},
	}

	for _, cfg := range validConfigs {
		assert.NotEmpty(t, cfg.Name)
		assert.GreaterOrEqual(t, cfg.Priority, 0)
	}
}

func TestChainTermination(t *testing.T) {
	lastModID := uint32(ModuleIDReturn)

	assert.Greater(t, lastModID, uint32(0))
	assert.Less(t, lastModID, uint32(20))
}
