package common

import (
	"fmt"

	"github.com/livp123/netxfw/internal/config"
	"github.com/livp123/netxfw/internal/core"
	"github.com/livp123/netxfw/internal/utils/logger"
	"github.com/livp123/netxfw/internal/xdp"
)

// GetManager returns an initialized XDPManager connected to the pinned maps.
// GetManager 返回一个连接到固定 Map 的初始化 XDPManager。
func GetManager() (core.XDPManager, error) {
	pinPath := config.GetPinPath()
	mgr, err := xdp.NewManagerFromPins(pinPath, logger.Get(nil))
	if err != nil {
		return nil, fmt.Errorf("failed to load XDP manager from %s: %w", pinPath, err)
	}
	return xdp.NewAdapter(mgr), nil
}
