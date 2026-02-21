package mock

import (
	"testing"
	"time"

	"github.com/netxfw/netxfw/pkg/sdk"
)

// TestMockStatsAPI tests MockStatsAPI
// TestMockStatsAPI 测试 MockStatsAPI
func TestMockStatsAPI(t *testing.T) {
	m := new(MockStatsAPI)

	// Test GetCounters
	// 测试 GetCounters
	m.On("GetCounters").Return(uint64(100), uint64(50), nil)
	pass, drop, err := m.GetCounters()
	if err != nil {
		t.Errorf("GetCounters should not error: %v", err)
	}
	if pass != 100 || drop != 50 {
		t.Errorf("GetCounters returned (%d, %d), expected (100, 50)", pass, drop)
	}

	// Test GetLockedIPCount
	// 测试 GetLockedIPCount
	m.On("GetLockedIPCount").Return(10, nil)
	count, err := m.GetLockedIPCount()
	if err != nil {
		t.Errorf("GetLockedIPCount should not error: %v", err)
	}
	if count != 10 {
		t.Errorf("GetLockedIPCount returned %d, expected 10", count)
	}

	// Test GetDropDetails
	// 测试 GetDropDetails
	m.On("GetDropDetails").Return([]sdk.DropDetailEntry{}, nil)
	details, err := m.GetDropDetails()
	if err != nil {
		t.Errorf("GetDropDetails should not error: %v", err)
	}
	if details == nil {
		t.Error("GetDropDetails should return non-nil slice")
	}

	// Test GetPassDetails
	// 测试 GetPassDetails
	m.On("GetPassDetails").Return([]sdk.DropDetailEntry{}, nil)
	passDetails, err := m.GetPassDetails()
	if err != nil {
		t.Errorf("GetPassDetails should not error: %v", err)
	}
	if passDetails == nil {
		t.Error("GetPassDetails should return non-nil slice")
	}
}

// TestMockConntrackAPI tests MockConntrackAPI
// TestMockConntrackAPI 测试 MockConntrackAPI
func TestMockConntrackAPI(t *testing.T) {
	m := new(MockConntrackAPI)

	// Test Count
	// 测试 Count
	m.On("Count").Return(100, nil)
	count, err := m.Count()
	if err != nil {
		t.Errorf("Count should not error: %v", err)
	}
	if count != 100 {
		t.Errorf("Count returned %d, expected 100", count)
	}

	// Test List
	// 测试 List
	m.On("List").Return([]sdk.ConntrackEntry{}, nil)
	entries, err := m.List()
	if err != nil {
		t.Errorf("List should not error: %v", err)
	}
	if entries == nil {
		t.Error("List should return non-nil slice")
	}
}

// TestMockSecurityAPI tests MockSecurityAPI
// TestMockSecurityAPI 测试 MockSecurityAPI
func TestMockSecurityAPI(t *testing.T) {
	m := new(MockSecurityAPI)

	// Test SetDefaultDeny
	// 测试 SetDefaultDeny
	m.On("SetDefaultDeny", true).Return(nil)
	err := m.SetDefaultDeny(true)
	if err != nil {
		t.Errorf("SetDefaultDeny should not error: %v", err)
	}

	// Test SetEnableAFXDP
	// 测试 SetEnableAFXDP
	m.On("SetEnableAFXDP", true).Return(nil)
	err = m.SetEnableAFXDP(true)
	if err != nil {
		t.Errorf("SetEnableAFXDP should not error: %v", err)
	}

	// Test SetDropFragments
	// 测试 SetDropFragments
	m.On("SetDropFragments", true).Return(nil)
	err = m.SetDropFragments(true)
	if err != nil {
		t.Errorf("SetDropFragments should not error: %v", err)
	}

	// Test SetStrictTCP
	// 测试 SetStrictTCP
	m.On("SetStrictTCP", true).Return(nil)
	err = m.SetStrictTCP(true)
	if err != nil {
		t.Errorf("SetStrictTCP should not error: %v", err)
	}

	// Test SetSYNLimit
	// 测试 SetSYNLimit
	m.On("SetSYNLimit", true).Return(nil)
	err = m.SetSYNLimit(true)
	if err != nil {
		t.Errorf("SetSYNLimit should not error: %v", err)
	}

	// Test SetConntrack
	// 测试 SetConntrack
	m.On("SetConntrack", true).Return(nil)
	err = m.SetConntrack(true)
	if err != nil {
		t.Errorf("SetConntrack should not error: %v", err)
	}

	// Test SetConntrackTimeout
	// 测试 SetConntrackTimeout
	m.On("SetConntrackTimeout", time.Hour).Return(nil)
	err = m.SetConntrackTimeout(time.Hour)
	if err != nil {
		t.Errorf("SetConntrackTimeout should not error: %v", err)
	}

	// Test SetBogonFilter
	// 测试 SetBogonFilter
	m.On("SetBogonFilter", true).Return(nil)
	err = m.SetBogonFilter(true)
	if err != nil {
		t.Errorf("SetBogonFilter should not error: %v", err)
	}

	// Test SetAutoBlock
	// 测试 SetAutoBlock
	m.On("SetAutoBlock", true).Return(nil)
	err = m.SetAutoBlock(true)
	if err != nil {
		t.Errorf("SetAutoBlock should not error: %v", err)
	}

	// Test SetAutoBlockExpiry
	// 测试 SetAutoBlockExpiry
	m.On("SetAutoBlockExpiry", time.Hour).Return(nil)
	err = m.SetAutoBlockExpiry(time.Hour)
	if err != nil {
		t.Errorf("SetAutoBlockExpiry should not error: %v", err)
	}
}

// TestMockSDK tests MockSDK
// TestMockSDK 测试 MockSDK
func TestMockSDK(t *testing.T) {
	m := new(MockSDK)

	// Test GetStats
	// 测试 GetStats
	m.On("GetStats").Return(uint64(100), uint64(50))
	pass, drop := m.GetStats()
	if pass != 100 || drop != 50 {
		t.Errorf("GetStats returned (%d, %d), expected (100, 50)", pass, drop)
	}
}
