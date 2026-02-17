package mock

import (
	"time"

	"github.com/livp123/netxfw/pkg/sdk"
	"github.com/stretchr/testify/mock"
)

// MockStatsAPI is a mock implementation of the StatsAPI interface
type MockStatsAPI struct {
	mock.Mock
}

func (m *MockStatsAPI) GetCounters() (uint64, uint64, error) {
	args := m.Called()
	return args.Get(0).(uint64), args.Get(1).(uint64), args.Error(2)
}

func (m *MockStatsAPI) GetLockedIPCount() (int, error) {
	args := m.Called()
	return args.Int(0), args.Error(1)
}

func (m *MockStatsAPI) GetDropDetails() ([]sdk.DropDetailEntry, error) {
	args := m.Called()
	return args.Get(0).([]sdk.DropDetailEntry), args.Error(1)
}

func (m *MockStatsAPI) GetPassDetails() ([]sdk.DropDetailEntry, error) {
	args := m.Called()
	return args.Get(0).([]sdk.DropDetailEntry), args.Error(1)
}

// MockConntrackAPI is a mock implementation of the ConntrackAPI interface
type MockConntrackAPI struct {
	mock.Mock
}

func (m *MockConntrackAPI) GetConntrackCount() (int, error) {
	args := m.Called()
	return args.Int(0), args.Error(1)
}

func (m *MockConntrackAPI) ListConntrackEntries() ([]sdk.ConntrackEntry, error) {
	args := m.Called()
	return args.Get(0).([]sdk.ConntrackEntry), args.Error(1)
}

// MockSecurityAPI is a mock implementation of the SecurityAPI interface
type MockSecurityAPI struct {
	mock.Mock
}

func (m *MockSecurityAPI) SetDefaultDeny(enable bool) error {
	args := m.Called(enable)
	return args.Error(0)
}

func (m *MockSecurityAPI) SetEnableAFXDP(enable bool) error {
	args := m.Called(enable)
	return args.Error(0)
}

func (m *MockSecurityAPI) SetDropFragments(enable bool) error {
	args := m.Called(enable)
	return args.Error(0)
}

func (m *MockSecurityAPI) SetStrictTCP(enable bool) error {
	args := m.Called(enable)
	return args.Error(0)
}

func (m *MockSecurityAPI) SetSYNLimit(enable bool) error {
	args := m.Called(enable)
	return args.Error(0)
}

func (m *MockSecurityAPI) SetConntrack(enable bool) error {
	args := m.Called(enable)
	return args.Error(0)
}

func (m *MockSecurityAPI) SetConntrackTimeout(timeout time.Duration) error {
	args := m.Called(timeout)
	return args.Error(0)
}

func (m *MockSecurityAPI) SetBogonFilter(enable bool) error {
	args := m.Called(enable)
	return args.Error(0)
}

func (m *MockSecurityAPI) SetAutoBlock(enable bool) error {
	args := m.Called(enable)
	return args.Error(0)
}

func (m *MockSecurityAPI) SetAutoBlockExpiry(duration time.Duration) error {
	args := m.Called(duration)
	return args.Error(0)
}

// MockSDK is a mock implementation of the SDK
type MockSDK struct {
	mock.Mock
	Stats     *MockStatsAPI
	Conntrack *MockConntrackAPI
	Security  *MockSecurityAPI
}

func (m *MockSDK) GetStats() (uint64, uint64) {
	args := m.Called()
	return args.Get(0).(uint64), args.Get(1).(uint64)
}

func (m *MockSDK) GetManager() sdk.ManagerInterface {
	args := m.Called()
	return args.Get(0).(sdk.ManagerInterface)
}

// Additional methods as needed for testing
