package sdk

import (
	"context"

	"github.com/netxfw/netxfw/internal/plugins/types"
)

// PluginContext provides the environment for a plugin to operate in.
// It wraps the XDP manager and global configuration, offering a unified access point for plugins.
// PluginContext 为插件运行提供环境。
// 它封装了 XDP 管理器和全局配置，为插件提供统一的访问点。
type PluginContext struct {
	context.Context
	// Firewall provides access to high-level firewall operations.
	// Firewall 提供对高级防火墙操作的访问。
	Firewall Firewall
	// Manager provides access to low-level XDP operations and BPF maps.
	// (Internal use only, prefer Firewall for high-level plugins)
	// Manager 提供对底层 XDP 操作和 BPF Map 的访问。
	// （仅限内部使用，高级插件优先使用 Firewall）
	Manager ManagerInterface
	// Config holds the current global configuration snapshot.
	// Config 保存当前的全局配置快照。
	Config *types.GlobalConfig
	// Logger is the standard logger for plugins.
	// Logger 是插件的标准日志记录器。
	Logger Logger
	// SDK provides structured high-level APIs (Blacklist, Whitelist, Rule, etc.).
	// SDK 提供结构化的高级 API（黑名单、白名单、规则等）。
	SDK *SDK
}

// Logger defines the logging interface for plugins.
// It abstracts the underlying logging implementation to allow flexibility.
// Logger 为插件定义日志接口。
// 它抽象了底层的日志实现，以允许灵活性。
type Logger interface {
	Infof(format string, args ...interface{})
	Warnf(format string, args ...interface{})
	Errorf(format string, args ...interface{})
}

// Plugin defines the standard interface for all netxfw plugins.
// Implementing this interface allows a component to be loaded and managed by the netxfw core.
// Plugin 为所有 netxfw 插件定义标准接口。
// 实现此接口允许组件被 netxfw 核心加载和管理。
type Plugin interface {
	// Name returns the unique identifier for the plugin.
	// It is used for logging, configuration mapping, and status reporting.
	// Name 返回插件的唯一标识符。
	// 它用于日志记录、配置映射和状态报告。
	Name() string

	// Init initializes the plugin with configuration.
	// This is called once when the plugin is loaded.
	// Init 使用配置初始化插件。
	// 当插件加载时调用一次。
	Init(ctx *PluginContext) error

	// Start begins the plugin's execution.
	// This is called after Init and whenever the system starts.
	// Start 开始插件的执行。
	// 在 Init 之后以及系统启动时调用。
	Start(ctx *PluginContext) error

	// Stop gracefully shuts down the plugin.
	// This should release any resources (goroutines, file handles, etc.).
	// Stop 优雅地关闭插件。
	// 这应该释放任何资源（goroutine、文件句柄等）。
	Stop() error

	// Reload updates the plugin configuration without a full restart.
	// It is called during a hot-reload event (e.g., 'system reload').
	// Reload 在不完全重启的情况下更新插件配置。
	// 它在热重载事件（例如 'system reload'）期间调用。
	Reload(ctx *PluginContext) error

	// DefaultConfig returns the default configuration structure for the plugin.
	// This structure is used to parse the YAML configuration.
	// DefaultConfig 返回插件的默认配置结构。
	// 此结构用于解析 YAML 配置。
	DefaultConfig() any

	// Validate checks if the configuration is valid before applying.
	// It should return an error if the configuration is invalid.
	// Validate 在应用之前检查配置是否有效。
	// 如果配置无效，它应该返回错误。
	Validate(config *types.GlobalConfig) error

	// Type returns the type of the plugin (Core or Extension).
	// Core plugins are required for the system to function.
	// Type 返回插件的类型（Core 或 Extension）。
	// Core 插件是系统运行所必需的。
	Type() PluginType
}

// PluginType defines the criticality of a plugin.
// PluginType 定义插件的重要性。
type PluginType int

const (
	// PluginTypeCore indicates a critical plugin that must load successfully.
	// PluginTypeCore 表示必须成功加载的关键插件。
	PluginTypeCore PluginType = iota
	// PluginTypeExtension indicates an optional plugin.
	// PluginTypeExtension 表示可选插件。
	PluginTypeExtension
)
