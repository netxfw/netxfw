package daemon_test

import (
	"testing"

	"github.com/livp123/netxfw/internal/daemon"
	"github.com/livp123/netxfw/internal/xdp"
	"github.com/stretchr/testify/assert"
)

// TestDaemonOptions tests daemon options creation
// TestDaemonOptions 测试守护进程选项创建
func TestDaemonOptions(t *testing.T) {
	// Test daemon options creation
	// 测试守护进程选项创建
	mockMgr := xdp.NewMockManager()

	opts := &daemon.DaemonOptions{
		Manager: mockMgr,
	}

	assert.NotNil(t, opts.Manager)
	assert.Equal(t, mockMgr, opts.Manager)
}
