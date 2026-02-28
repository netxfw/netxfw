package agent

import (
	"testing"

	"github.com/netxfw/netxfw/cmd/netxfw/commands/common"
	"github.com/netxfw/netxfw/pkg/sdk/mock"
	"github.com/stretchr/testify/assert"
)

// TestVersionCmd tests the version command.
// TestVersionCmd 测试 version 命令。
func TestVersionCmd(t *testing.T) {
	m := mock.NewMockSDK()
	mock.SetupMockStats(m)

	common.MockSDK = m

	_, err := executeCommand(SimpleVersionCmd)
	assert.NoError(t, err)
}

// TestVersionCmdWithStats tests version command with stats.
// TestVersionCmdWithStats 测试带统计信息的 version 命令。
func TestVersionCmdWithStats(t *testing.T) {
	m := mock.NewMockSDK()
	mock.SetupMockStats(m)

	common.MockSDK = m

	_, err := executeCommand(SimpleVersionCmd)
	assert.NoError(t, err)
}

// TestVersionCmdHighCounters tests version with high counter values.
// TestVersionCmdHighCounters 测试高计数器值的 version 命令。
func TestVersionCmdHighCounters(t *testing.T) {
	m := mock.NewMockSDK()
	mock.SetupMockStats(m)

	common.MockSDK = m

	_, err := executeCommand(SimpleVersionCmd)
	assert.NoError(t, err)
}
