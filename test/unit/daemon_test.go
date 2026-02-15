package unit

import (
	"testing"

	"github.com/livp123/netxfw/internal/daemon"
	"github.com/livp123/netxfw/internal/xdp"
	"github.com/stretchr/testify/assert"
)

func TestDaemonOptions(t *testing.T) {
	// Test daemon options creation
	mockMgr := xdp.NewMockManager()

	opts := &daemon.DaemonOptions{
		Manager: mockMgr,
	}

	assert.NotNil(t, opts.Manager)
	assert.Equal(t, mockMgr, opts.Manager)
}
