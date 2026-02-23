package daemon

import (
	"github.com/netxfw/netxfw/internal/xdp"
)

// DaemonOptions configuration options for the daemon
// DaemonOptions 守护进程的配置选项
type DaemonOptions struct {
	// Manager allows injecting a custom/mock XDP manager.
	// Manager 允许注入自定义/模拟的 XDP 管理器。
	// If nil, the default manager will be created.
	// 如果为 nil，将创建默认管理器。
	Manager xdp.ManagerInterface

	// Interfaces specifies the network interfaces to bind to.
	// If nil or empty, all interfaces will be used.
	// Interfaces 指定要绑定的网络接口。
	// 如果为 nil 或为空，则使用所有接口。
	Interfaces []string
}
