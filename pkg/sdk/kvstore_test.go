package sdk

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKVStore(t *testing.T) {
	s := &kvStoreImpl{}

	// Test Set and Get
	s.Set("key1", "value1")
	val, ok := s.Get("key1")
	assert.True(t, ok)
	assert.Equal(t, "value1", val)

	// Test Get non-existent
	val, ok = s.Get("key2")
	assert.False(t, ok)
	assert.Nil(t, val)

	// Test Delete
	s.Delete("key1")
	val, ok = s.Get("key1")
	assert.False(t, ok)
	assert.Nil(t, val)

	// Test Complex Type
	type Complex struct {
		ID   int
		Name string
	}
	c := Complex{ID: 1, Name: "Test"}
	s.Set("complex", c)
	val, ok = s.Get("complex")
	assert.True(t, ok)
	assert.Equal(t, c, val)
}

func TestNewSDK_StoreInitialized(t *testing.T) {
	sdk := NewSDK(nil)
	assert.NotNil(t, sdk.Store)
	
	sdk.Store.Set("test", 123)
	val, ok := sdk.Store.Get("test")
	assert.True(t, ok)
	assert.Equal(t, 123, val)
}
