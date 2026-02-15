package unit

import (
	"testing"

	"github.com/livp123/netxfw/internal/xdp"
	"github.com/stretchr/testify/assert"
)

func TestXDPMiscFunctions(t *testing.T) {
	mockMgr := xdp.NewMockManager()

	// Test basic operations that should work with mock
	count, err := mockMgr.GetLockedIPCount()
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, count, 0)

	count, err = mockMgr.GetWhitelistCount()
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, count, 0)

	// Test close operation
	err = mockMgr.Close()
	assert.NoError(t, err)
}

func TestXDPLifecycle(t *testing.T) {
	// Test that we can create and use the mock manager properly
	mockMgr := xdp.NewMockManager()

	// Add some data
	err := mockMgr.AddBlacklistIP("1.2.3.4/32")
	assert.NoError(t, err)

	// Verify it was added
	inBlacklist, err := mockMgr.IsIPInBlacklist("1.2.3.4/32")
	assert.NoError(t, err)
	assert.True(t, inBlacklist)

	// Remove it
	err = mockMgr.RemoveBlacklistIP("1.2.3.4/32")
	assert.NoError(t, err)

	// Verify it was removed
	inBlacklist, err = mockMgr.IsIPInBlacklist("1.2.3.4/32")
	assert.NoError(t, err)
	assert.False(t, inBlacklist)
}
