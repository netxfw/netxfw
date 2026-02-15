package sdk_test

import (
	"testing"
	"time"

	"github.com/livp123/netxfw/internal/xdp"
	"github.com/livp123/netxfw/pkg/sdk"
)

func TestEventBusIntegration(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)

	// Channel to receive events
	eventCh := make(chan sdk.Event, 1)

	// Subscribe to rate limit block events
	s.EventBus.Subscribe(sdk.EventTypeRateLimitBlock, func(e sdk.Event) {
		eventCh <- e
	})

	// Trigger a manual blacklist add, which should publish an event
	testIP := "192.168.1.100/32"
	if err := s.Blacklist.Add(testIP); err != nil {
		t.Fatalf("Failed to add blacklist IP: %v", err)
	}

	// Wait for event
	select {
	case e := <-eventCh:
		if e.Type != sdk.EventTypeRateLimitBlock {
			t.Errorf("Expected event type %s, got %s", sdk.EventTypeRateLimitBlock, e.Type)
		}
		// Payload might be interface{}, assert string
		payloadStr, ok := e.Payload.(string)
		if !ok {
			t.Errorf("Expected payload to be string, got %T", e.Payload)
		} else if payloadStr != testIP {
			t.Errorf("Expected payload %s, got %s", testIP, payloadStr)
		}
		
		if e.Source != "manual_blacklist" {
			t.Errorf("Expected source manual_blacklist, got %s", e.Source)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Timeout waiting for event")
	}
}

func TestSDKComponents(t *testing.T) {
	mockMgr := xdp.NewMockManager()
	s := sdk.NewSDK(mockMgr)

	if s.Blacklist == nil {
		t.Error("Blacklist API not initialized")
	}
	if s.Whitelist == nil {
		t.Error("Whitelist API not initialized")
	}
	if s.Rule == nil {
		t.Error("Rule API not initialized")
	}
	if s.Stats == nil {
		t.Error("Stats API not initialized")
	}
	if s.EventBus == nil {
		t.Error("EventBus not initialized")
	}
}
