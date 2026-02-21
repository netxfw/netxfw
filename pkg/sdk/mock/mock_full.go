package mock

import (
	"time"

	"github.com/netxfw/netxfw/internal/plugins/types"
	"github.com/netxfw/netxfw/pkg/sdk"
	"github.com/stretchr/testify/mock"
)

// MockBlacklistAPI is a mock implementation of the BlacklistAPI interface.
// MockBlacklistAPI 是 BlacklistAPI 接口的 mock 实现。
type MockBlacklistAPI struct {
	mock.Mock
}

func (m *MockBlacklistAPI) Add(cidr string) error {
	args := m.Called(cidr)
	return args.Error(0)
}

func (m *MockBlacklistAPI) AddWithDuration(cidr string, duration time.Duration) error {
	args := m.Called(cidr, duration)
	return args.Error(0)
}

func (m *MockBlacklistAPI) AddWithFile(cidr string, file string) error {
	args := m.Called(cidr, file)
	return args.Error(0)
}

func (m *MockBlacklistAPI) Remove(cidr string) error {
	args := m.Called(cidr)
	return args.Error(0)
}

func (m *MockBlacklistAPI) Clear() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockBlacklistAPI) Contains(ip string) (bool, error) {
	args := m.Called(ip)
	return args.Bool(0), args.Error(1)
}

func (m *MockBlacklistAPI) List(limit int, search string) ([]sdk.BlockedIP, int, error) {
	args := m.Called(limit, search)
	if args.Get(0) == nil {
		return nil, args.Int(1), args.Error(2)
	}
	return args.Get(0).([]sdk.BlockedIP), args.Int(1), args.Error(2)
}

// MockWhitelistAPI is a mock implementation of the WhitelistAPI interface.
// MockWhitelistAPI 是 WhitelistAPI 接口的 mock 实现。
type MockWhitelistAPI struct {
	mock.Mock
}

func (m *MockWhitelistAPI) Add(cidr string, port uint16) error {
	args := m.Called(cidr, port)
	return args.Error(0)
}

func (m *MockWhitelistAPI) AddWithPort(cidr string, port uint16) error {
	args := m.Called(cidr, port)
	return args.Error(0)
}

func (m *MockWhitelistAPI) Remove(cidr string) error {
	args := m.Called(cidr)
	return args.Error(0)
}

func (m *MockWhitelistAPI) Clear() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockWhitelistAPI) Contains(ip string) (bool, error) {
	args := m.Called(ip)
	return args.Bool(0), args.Error(1)
}

func (m *MockWhitelistAPI) List(limit int, search string) ([]string, int, error) {
	args := m.Called(limit, search)
	if args.Get(0) == nil {
		return nil, args.Int(1), args.Error(2)
	}
	return args.Get(0).([]string), args.Int(1), args.Error(2)
}

// MockRuleAPI is a mock implementation of the RuleAPI interface.
// MockRuleAPI 是 RuleAPI 接口的 mock 实现。
type MockRuleAPI struct {
	mock.Mock
}

func (m *MockRuleAPI) Add(cidr string, port uint16, action uint8) error {
	args := m.Called(cidr, port, action)
	return args.Error(0)
}

func (m *MockRuleAPI) Remove(cidr string, port uint16) error {
	args := m.Called(cidr, port)
	return args.Error(0)
}

func (m *MockRuleAPI) Clear() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockRuleAPI) List(isIPv6 bool, limit int, search string) ([]sdk.IPPortRule, int, error) {
	args := m.Called(isIPv6, limit, search)
	if args.Get(0) == nil {
		return nil, args.Int(1), args.Error(2)
	}
	return args.Get(0).([]sdk.IPPortRule), args.Int(1), args.Error(2)
}

func (m *MockRuleAPI) AddIPPortRule(cidr string, port uint16, action uint8) error {
	args := m.Called(cidr, port, action)
	return args.Error(0)
}

func (m *MockRuleAPI) RemoveIPPortRule(cidr string, port uint16) error {
	args := m.Called(cidr, port)
	return args.Error(0)
}

func (m *MockRuleAPI) ListIPPortRules(limit int, search string) ([]sdk.IPPortRule, int, error) {
	args := m.Called(limit, search)
	if args.Get(0) == nil {
		return nil, args.Int(1), args.Error(2)
	}
	return args.Get(0).([]sdk.IPPortRule), args.Int(1), args.Error(2)
}

func (m *MockRuleAPI) AllowPort(port uint16) error {
	args := m.Called(port)
	return args.Error(0)
}

func (m *MockRuleAPI) RemoveAllowedPort(port uint16) error {
	args := m.Called(port)
	return args.Error(0)
}

func (m *MockRuleAPI) ListAllowedPorts() ([]uint16, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]uint16), args.Error(1)
}

func (m *MockRuleAPI) AddRateLimitRule(ip string, rate, burst uint64) error {
	args := m.Called(ip, rate, burst)
	return args.Error(0)
}

func (m *MockRuleAPI) RemoveRateLimitRule(ip string) error {
	args := m.Called(ip)
	return args.Error(0)
}

func (m *MockRuleAPI) ListRateLimitRules(limit int, search string) (map[string]sdk.RateLimitConf, int, error) {
	args := m.Called(limit, search)
	if args.Get(0) == nil {
		return nil, args.Int(1), args.Error(2)
	}
	return args.Get(0).(map[string]sdk.RateLimitConf), args.Int(1), args.Error(2)
}

// MockSyncAPI is a mock implementation of the SyncAPI interface.
// MockSyncAPI 是 SyncAPI 接口的 mock 实现。
type MockSyncAPI struct {
	mock.Mock
}

func (m *MockSyncAPI) ToConfig(cfg *types.GlobalConfig) error {
	args := m.Called(cfg)
	return args.Error(0)
}

func (m *MockSyncAPI) ToMap(cfg *types.GlobalConfig, overwrite bool) error {
	args := m.Called(cfg, overwrite)
	return args.Error(0)
}

func (m *MockSyncAPI) VerifyAndRepair(cfg *types.GlobalConfig) error {
	args := m.Called(cfg)
	return args.Error(0)
}

// MockEventBus is a mock implementation of the EventBus interface.
// MockEventBus 是 EventBus 接口的 mock 实现。
type MockEventBus struct {
	mock.Mock
}

func (m *MockEventBus) Subscribe(eventType sdk.EventType, handler sdk.EventHandler) {
	m.Called(eventType, handler)
}

func (m *MockEventBus) Unsubscribe(eventType sdk.EventType, handler sdk.EventHandler) {
	m.Called(eventType, handler)
}

func (m *MockEventBus) Publish(event sdk.Event) {
	m.Called(event)
}

// MockKVStore is a mock implementation of the KVStore interface.
// MockKVStore 是 KVStore 接口的 mock 实现。
type MockKVStore struct {
	mock.Mock
}

func (m *MockKVStore) Set(key string, value any) {
	m.Called(key, value)
}

func (m *MockKVStore) Get(key string) (any, bool) {
	args := m.Called(key)
	return args.Get(0), args.Bool(1)
}

func (m *MockKVStore) Delete(key string) {
	m.Called(key)
}

// NewMockSDK creates a new mock SDK with all interfaces mocked.
// NewMockSDK 创建一个新的 mock SDK，所有接口都被 mock。
func NewMockSDK() *sdk.SDK {
	return &sdk.SDK{
		Blacklist: &MockBlacklistAPI{},
		Whitelist: &MockWhitelistAPI{},
		Rule:      &MockRuleAPI{},
		Stats:     &MockStatsAPI{},
		Conntrack: &MockConntrackAPI{},
		Security:  &MockSecurityAPI{},
		Sync:      &MockSyncAPI{},
		EventBus:  &MockEventBus{},
		Store:     &MockKVStore{},
	}
}

// SetupMockBlacklist sets up the mock blacklist with default behavior.
// SetupMockBlacklist 设置 mock 黑名单的默认行为。
func SetupMockBlacklist(m *sdk.SDK) *MockBlacklistAPI {
	if mb, ok := m.Blacklist.(*MockBlacklistAPI); ok {
		mb.On("Add", mock.Anything).Return(nil)
		mb.On("Remove", mock.Anything).Return(nil)
		mb.On("Clear").Return(nil)
		mb.On("Contains", mock.Anything).Return(true, nil)
		mb.On("List", mock.Anything, mock.Anything).Return([]sdk.BlockedIP{}, 0, nil)
		return mb
	}
	return nil
}

// SetupMockWhitelist sets up the mock whitelist with default behavior.
// SetupMockWhitelist 设置 mock 白名单的默认行为。
func SetupMockWhitelist(m *sdk.SDK) *MockWhitelistAPI {
	if mw, ok := m.Whitelist.(*MockWhitelistAPI); ok {
		mw.On("Add", mock.Anything, mock.Anything).Return(nil)
		mw.On("Remove", mock.Anything).Return(nil)
		mw.On("Clear").Return(nil)
		mw.On("Contains", mock.Anything).Return(true, nil)
		mw.On("List", mock.Anything, mock.Anything).Return([]string{}, 0, nil)
		return mw
	}
	return nil
}

// SetupMockRule sets up the mock rule with default behavior.
// SetupMockRule 设置 mock 规则的默认行为。
func SetupMockRule(m *sdk.SDK) *MockRuleAPI {
	if mr, ok := m.Rule.(*MockRuleAPI); ok {
		mr.On("Add", mock.Anything, mock.Anything, mock.Anything).Return(nil)
		mr.On("Remove", mock.Anything, mock.Anything).Return(nil)
		mr.On("Clear").Return(nil)
		mr.On("List", mock.Anything, mock.Anything, mock.Anything).Return([]sdk.IPPortRule{}, 0, nil)
		mr.On("AddIPPortRule", mock.Anything, mock.Anything, mock.Anything).Return(nil)
		mr.On("RemoveIPPortRule", mock.Anything, mock.Anything).Return(nil)
		mr.On("ListIPPortRules", mock.Anything, mock.Anything).Return([]sdk.IPPortRule{}, 0, nil)
		mr.On("AllowPort", mock.Anything).Return(nil)
		mr.On("RemoveAllowedPort", mock.Anything).Return(nil)
		mr.On("ListAllowedPorts").Return([]uint16{}, nil)
		mr.On("AddRateLimitRule", mock.Anything, mock.Anything, mock.Anything).Return(nil)
		mr.On("RemoveRateLimitRule", mock.Anything).Return(nil)
		mr.On("ListRateLimitRules", mock.Anything, mock.Anything).Return(map[string]sdk.RateLimitConf{}, 0, nil)
		return mr
	}
	return nil
}

// SetupMockStats sets up the mock stats with default behavior.
// SetupMockStats 设置 mock 统计的默认行为。
func SetupMockStats(m *sdk.SDK) *MockStatsAPI {
	if ms, ok := m.Stats.(*MockStatsAPI); ok {
		ms.On("GetCounters").Return(uint64(1000), uint64(500), nil)
		ms.On("GetLockedIPCount").Return(0, nil)
		ms.On("GetDropDetails").Return([]sdk.DropDetailEntry{}, nil)
		ms.On("GetPassDetails").Return([]sdk.DropDetailEntry{}, nil)
		return ms
	}
	return nil
}

// SetupMockConntrack sets up the mock conntrack with default behavior.
// SetupMockConntrack 设置 mock 连接跟踪的默认行为。
func SetupMockConntrack(m *sdk.SDK) *MockConntrackAPI {
	if mc, ok := m.Conntrack.(*MockConntrackAPI); ok {
		mc.On("List").Return([]sdk.ConntrackEntry{}, nil)
		mc.On("Count").Return(0, nil)
		return mc
	}
	return nil
}
