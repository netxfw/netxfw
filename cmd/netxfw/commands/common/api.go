package common

import (
	"context"

	"github.com/livp123/netxfw/internal/core"
)

// System commands
// 系统命令
var (
	InitConfiguration   func(ctx context.Context)
	ShowStatus          func(ctx context.Context, mgr core.XDPManager) error
	ShowTopStats        func(ctx context.Context, mgr core.XDPManager, limit int, sortBy string) error
	TestConfiguration   func(ctx context.Context)
	RunDaemon           func(ctx context.Context)
	InstallXDP          func(ctx context.Context, interfaces []string) error
	ReloadXDP           func(ctx context.Context, interfaces []string) error
	RemoveXDP           func(ctx context.Context, interfaces []string) error
	SyncToConfig        func(ctx context.Context, mgr core.XDPManager) error
	SyncToMap           func(ctx context.Context, mgr core.XDPManager) error
	SyncDefaultDeny     func(ctx context.Context, mgr core.XDPManager, enable bool) error
	SyncEnableRateLimit func(ctx context.Context, mgr core.XDPManager, enable bool) error
	SyncEnableAFXDP     func(ctx context.Context, mgr core.XDPManager, enable bool) error
)

// Rule commands
// 规则命令
var (
	EnsureStandaloneMode      func()
	SyncLockMap      func(ctx context.Context, mgr core.XDPManager, cidr string, lock bool, force bool) error
	SyncWhitelistMap func(ctx context.Context, mgr core.XDPManager, cidr string, port uint16, allow bool, force bool) error
	SyncIPPortRule            func(ctx context.Context, mgr core.XDPManager, ip string, port uint16, protocol uint8, allow bool) error
	ShowIPPortRules           func(ctx context.Context, mgr core.XDPManager, limit int, search string) error
	ShowWhitelist             func(ctx context.Context, mgr core.XDPManager, limit int, search string) error
	ShowLockList              func(ctx context.Context, mgr core.XDPManager, limit int, search string) error
	ImportLockListFromFile    func(ctx context.Context, mgr core.XDPManager, filename string) error
	ImportWhitelistFromFile   func(ctx context.Context, mgr core.XDPManager, filename string) error
	ImportIPPortRulesFromFile func(ctx context.Context, mgr core.XDPManager, filename string) error
	ClearBlacklist            func(ctx context.Context, mgr core.XDPManager) error
)

// Security commands
// 安全命令
var (
	SyncDropFragments   func(ctx context.Context, mgr core.XDPManager, enable bool) error
	SyncStrictTCP       func(ctx context.Context, mgr core.XDPManager, enable bool) error
	SyncSYNLimit        func(ctx context.Context, mgr core.XDPManager, enable bool) error
	SyncBogonFilter     func(ctx context.Context, mgr core.XDPManager, enable bool) error
	SyncAutoBlock       func(ctx context.Context, mgr core.XDPManager, enable bool) error
	SyncAutoBlockExpiry func(ctx context.Context, mgr core.XDPManager, seconds uint32) error
)

// Limit commands
// 限速命令
var (
	SyncRateLimitRule  func(ctx context.Context, mgr core.XDPManager, ip string, rate uint64, burst uint64, add bool) error
	ShowRateLimitRules func(ctx context.Context, mgr core.XDPManager) error
)

// Port commands
// 端口命令
var (
	SyncAllowedPort func(ctx context.Context, mgr core.XDPManager, port uint16, add bool) error
)

// Web commands
// Web 命令
var (
	RunWebServer func(ctx context.Context, port int) error
)

// Conntrack commands
// 连接跟踪命令
var (
	ShowConntrack func(ctx context.Context, mgr core.XDPManager) error
)

// Quick commands
// 快速命令
var (
	AskConfirmation func(prompt string) bool
)
