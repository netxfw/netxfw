package unit

import (
	"testing"

	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/internal/xdp"
	"github.com/livp123/netxfw/pkg/sdk"
	"github.com/stretchr/testify/assert"
)

func TestSDK_Sync(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)

	// Test Sync operations
	// Note: We're testing with a mock manager, so some operations might be no-ops
	// Pass a valid config instead of nil to avoid null pointer dereference
	cfg := &types.GlobalConfig{}
	err := s.Sync.VerifyAndRepair(cfg)
	assert.NoError(t, err)
}

func TestSDK_Stats_GetLockedIPCount(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)

	// Test GetLockedIPCount - this should be available via Stats
	count, err := s.Stats.GetLockedIPCount()
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, count, 0)
}

func TestSDK_GetManager(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)

	// Test GetManager
	manager := s.GetManager()
	assert.NotNil(t, manager)
}

func TestSDK_KVStore(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)

	// Test KV Store operations
	s.Store.Set("test_key", "test_value")

	value, exists := s.Store.Get("test_key")
	assert.True(t, exists)
	assert.Equal(t, "test_value", value.(string))

	s.Store.Delete("test_key")
	_, exists = s.Store.Get("test_key")
	assert.False(t, exists)
}
