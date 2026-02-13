package plugins

import (
	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/internal/xdp"
)

// Plugin defines the interface for netxfw plugins
// Plugin 定义了 netxfw 插件的接口。
type Plugin interface {
	Name() string
	Init(config *types.GlobalConfig) error
	Start(manager *xdp.Manager) error
	Stop() error
	// InitConfig returns default configuration for this plugin
	// DefaultConfig 返回此插件的默认配置。
	DefaultConfig() interface{}
	// Validate checks the plugin configuration for errors
	// Validate 检查插件配置是否存在错误。
	Validate(config *types.GlobalConfig) error
	// Reload updates the plugin configuration without restarting
	// Reload 在不重启的情况下更新插件配置。
	Reload(config *types.GlobalConfig, manager *xdp.Manager) error
}
