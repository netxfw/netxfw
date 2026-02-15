package daemon

import (
	"github.com/livp123/netxfw/internal/xdp"
)

// DaemonOptions configuration options for the daemon
// DaemonOptions 守护进程的配置选项
type DaemonOptions struct {
	// Manager allows injecting a custom/mock XDP manager.
	// Manager 允许注入自定义/模拟的 XDP 管理器。
	// If nil, the default manager will be created.
	// 如果为 nil，将创建默认管理器。
	Manager xdp.ManagerInterface
}
