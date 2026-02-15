package unit

import (
	"testing"
	"time"

	"github.com/livp123/netxfw/internal/xdp"
	"github.com/livp123/netxfw/pkg/sdk"
	"github.com/stretchr/testify/assert"
)

func TestSDK_Blacklist(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)

	// Test Add
	err := s.Blacklist.Add("1.2.3.4/32")
	assert.NoError(t, err)

	// Test Contains
	exists, err := s.Blacklist.Contains("1.2.3.4/32")
	assert.NoError(t, err)
	assert.True(t, exists)

	// Test Remove
	err = s.Blacklist.Remove("1.2.3.4/32")
	assert.NoError(t, err)

	exists, err = s.Blacklist.Contains("1.2.3.4/32")
	assert.NoError(t, err)
	assert.False(t, exists)

	// Test AddWithDuration (Mock might not simulate expiry but should accept call)
	err = s.Blacklist.AddWithDuration("5.6.7.8/32", time.Minute)
	assert.NoError(t, err)
}

func TestSDK_Whitelist(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)

	// Test Add
	err := s.Whitelist.Add("10.0.0.1/32", 0)
	assert.NoError(t, err)

	// Test Contains
	exists, err := s.Whitelist.Contains("10.0.0.1/32")
	assert.NoError(t, err)
	assert.True(t, exists)

	// Test Remove
	err = s.Whitelist.Remove("10.0.0.1/32")
	assert.NoError(t, err)

	exists, err = s.Whitelist.Contains("10.0.0.1/32")
	assert.NoError(t, err)
	assert.False(t, exists)
}

func TestSDK_Rule(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)

	// Test Add
	err := s.Rule.Add("192.168.1.1/32", 80, 1) // 1=Allow
	assert.NoError(t, err)

	// Test List (MockManager needs to implement ListIPPortRules correctly for this to pass with items)
	rules, _, err := s.Rule.List(false, 10, "")
	assert.NoError(t, err)
	found := false
	for _, r := range rules {
		if r.IP == "192.168.1.1/32" && r.Port == 80 {
			found = true
			break
		}
	}
	assert.True(t, found, "Rule should exist")

	// Test Remove
	err = s.Rule.Remove("192.168.1.1/32", 80)
	assert.NoError(t, err)

	rules, _, _ = s.Rule.List(false, 10, "")
	found = false
	for _, r := range rules {
		if r.IP == "192.168.1.1/32" && r.Port == 80 {
			found = true
			break
		}
	}
	assert.False(t, found, "Rule should be removed")
}

func TestSDK_EventBus(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)

	received := make(chan sdk.Event, 1)
	handler := func(e sdk.Event) {
		received <- e
	}

	eventType := sdk.EventType("test_event")
	s.EventBus.Subscribe(eventType, handler)

	event := sdk.Event{
		Type:      eventType,
		Payload:   "test_payload",
		Timestamp: time.Now().Unix(),
		Source:    "unit_test",
	}
	s.EventBus.Publish(event)

	select {
	case e := <-received:
		assert.Equal(t, eventType, e.Type)
		assert.Equal(t, "test_payload", e.Payload)
	case <-time.After(1 * time.Second):
		t.Fatal("Timeout waiting for event")
	}
}
