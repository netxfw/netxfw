package agent

import (
	"bytes"
	"testing"
	"time"

	"github.com/livp123/netxfw/cmd/netxfw/commands/common"
	"github.com/livp123/netxfw/pkg/sdk"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockBlacklist
type MockBlacklist struct {
	mock.Mock
}

func (m *MockBlacklist) Add(cidr string) error {
	args := m.Called(cidr)
	return args.Error(0)
}
func (m *MockBlacklist) AddWithDuration(cidr string, duration time.Duration) error {
	args := m.Called(cidr, duration)
	return args.Error(0)
}
func (m *MockBlacklist) AddWithFile(cidr string, file string) error {
	args := m.Called(cidr, file)
	return args.Error(0)
}
func (m *MockBlacklist) Remove(cidr string) error {
	args := m.Called(cidr)
	return args.Error(0)
}
func (m *MockBlacklist) Clear() error {
	args := m.Called()
	return args.Error(0)
}
func (m *MockBlacklist) Contains(ip string) (bool, error) {
	args := m.Called(ip)
	return args.Bool(0), args.Error(1)
}
func (m *MockBlacklist) List(limit int, search string) ([]sdk.BlockedIP, int, error) {
	args := m.Called(limit, search)
	return args.Get(0).([]sdk.BlockedIP), args.Int(1), args.Error(2)
}

// MockWhitelist
type MockWhitelist struct {
	mock.Mock
}

func (m *MockWhitelist) Add(cidr string, port uint16) error {
	args := m.Called(cidr, port)
	return args.Error(0)
}
func (m *MockWhitelist) AddWithPort(cidr string, port uint16) error {
	args := m.Called(cidr, port)
	return args.Error(0)
}
func (m *MockWhitelist) Remove(cidr string) error {
	args := m.Called(cidr)
	return args.Error(0)
}
func (m *MockWhitelist) Clear() error {
	args := m.Called()
	return args.Error(0)
}
func (m *MockWhitelist) Contains(ip string) (bool, error) {
	args := m.Called(ip)
	return args.Bool(0), args.Error(1)
}
func (m *MockWhitelist) List(limit int, search string) ([]string, int, error) {
	args := m.Called(limit, search)
	return args.Get(0).([]string), args.Int(1), args.Error(2)
}

// MockRule
type MockRule struct {
	mock.Mock
}

func (m *MockRule) Add(cidr string, port uint16, action uint8) error {
	args := m.Called(cidr, port, action)
	return args.Error(0)
}
func (m *MockRule) Remove(cidr string, port uint16) error {
	args := m.Called(cidr, port)
	return args.Error(0)
}
func (m *MockRule) Clear() error {
	args := m.Called()
	return args.Error(0)
}
func (m *MockRule) List(isIPv6 bool, limit int, search string) ([]sdk.IPPortRule, int, error) {
	args := m.Called(isIPv6, limit, search)
	return args.Get(0).([]sdk.IPPortRule), args.Int(1), args.Error(2)
}
func (m *MockRule) AddIPPortRule(cidr string, port uint16, action uint8) error {
	args := m.Called(cidr, port, action)
	return args.Error(0)
}
func (m *MockRule) RemoveIPPortRule(cidr string, port uint16) error {
	args := m.Called(cidr, port)
	return args.Error(0)
}
func (m *MockRule) ListIPPortRules(limit int, search string) ([]sdk.IPPortRule, int, error) {
	args := m.Called(limit, search)
	return args.Get(0).([]sdk.IPPortRule), args.Int(1), args.Error(2)
}
func (m *MockRule) AllowPort(port uint16) error {
	args := m.Called(port)
	return args.Error(0)
}
func (m *MockRule) RemoveAllowedPort(port uint16) error {
	args := m.Called(port)
	return args.Error(0)
}
func (m *MockRule) AddRateLimitRule(ip string, rate, burst uint64) error {
	args := m.Called(ip, rate, burst)
	return args.Error(0)
}
func (m *MockRule) RemoveRateLimitRule(ip string) error {
	args := m.Called(ip)
	return args.Error(0)
}
func (m *MockRule) ListRateLimitRules(limit int, search string) (map[string]sdk.RateLimitConf, int, error) {
	args := m.Called(limit, search)
	return args.Get(0).(map[string]sdk.RateLimitConf), args.Int(1), args.Error(2)
}

func executeCommand(cmd *cobra.Command, args ...string) (string, error) {
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return buf.String(), err
}

func TestRuleAddCmd(t *testing.T) {
	mockBlacklist := new(MockBlacklist)
	mockWhitelist := new(MockWhitelist)
	mockRule := new(MockRule)

	common.MockSDK = &sdk.SDK{
		Blacklist: mockBlacklist,
		Whitelist: mockWhitelist,
		Rule:      mockRule,
	}

	// Test adding to blacklist
	mockBlacklist.On("Add", "1.2.3.4").Return(nil)
	mockWhitelist.On("Remove", "1.2.3.4").Return(nil)
	output, err := executeCommand(RuleCmd, "add", "1.2.3.4", "deny")
	assert.NoError(t, err)
	assert.Contains(t, output, "Added 1.2.3.4 to Blacklist")
	mockBlacklist.AssertExpectations(t)
	mockWhitelist.AssertExpectations(t)

	// Test adding to whitelist
	mockWhitelist.On("Add", "5.6.7.8", uint16(0)).Return(nil)
	mockBlacklist.On("Remove", "5.6.7.8").Return(nil)
	output, err = executeCommand(RuleCmd, "add", "5.6.7.8", "allow")
	assert.NoError(t, err)
	assert.Contains(t, output, "Added 5.6.7.8 to Whitelist")
	mockWhitelist.AssertExpectations(t)
	mockBlacklist.AssertExpectations(t)

	// Test adding IP+Port rule
	mockRule.On("AddIPPortRule", "10.0.0.1", uint16(80), uint8(2)).Return(nil)
	output, err = executeCommand(RuleCmd, "add", "10.0.0.1:80", "deny")
	assert.NoError(t, err)
	assert.Contains(t, output, "Rule added: 10.0.0.1:80 (Action: 2)")
	mockRule.AssertExpectations(t)
}

func TestRuleListCmd(t *testing.T) {
	mockBlacklist := new(MockBlacklist)
	mockWhitelist := new(MockWhitelist)
	mockRule := new(MockRule)

	common.MockSDK = &sdk.SDK{
		Blacklist: mockBlacklist,
		Whitelist: mockWhitelist,
		Rule:      mockRule,
	}

	mockWhitelist.On("List", 100, "").Return([]string{"1.1.1.1"}, 1, nil)
	mockBlacklist.On("List", 100, "").Return([]sdk.BlockedIP{{IP: "2.2.2.2"}}, 1, nil)
	mockRule.On("ListIPPortRules", 100, "").Return([]sdk.IPPortRule{{IP: "3.3.3.3", Port: 80, Action: 2}}, 1, nil)

	// Test list all
	output, err := executeCommand(RuleCmd, "list")
	assert.NoError(t, err)
	assert.Contains(t, output, "1.1.1.1")
	assert.Contains(t, output, "2.2.2.2")
	assert.Contains(t, output, "3.3.3.3:80")

	// Test list specific
	mockWhitelist.On("List", 100, "").Return([]string{"1.1.1.1"}, 1, nil)
	output, err = executeCommand(RuleCmd, "list", "allow")
	assert.NoError(t, err)
	assert.Contains(t, output, "1.1.1.1")
}
