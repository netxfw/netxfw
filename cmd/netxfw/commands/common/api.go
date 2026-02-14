package common

// System commands
// 系统命令
var (
	InitConfiguration   func()
	ShowStatus          func()
	ShowTopStats        func(limit int, sortBy string)
	TestConfiguration   func()
	RunDaemon           func()
	InstallXDP          func(interfaces []string)
	ReloadXDP           func(interfaces []string)
	RemoveXDP           func(interfaces []string)
	SyncToConfig        func()
	SyncToMap           func()
	SyncDefaultDeny     func(enable bool)
	SyncEnableRateLimit func(enable bool)
	SyncEnableAFXDP     func(enable bool)
)

// Rule commands
// 规则命令
var (
	EnsureStandaloneMode      func()
	SyncLockMap               func(ip string, lock bool)
	SyncWhitelistMap          func(ip string, port uint16, allow bool)
	SyncIPPortRule            func(ip string, port uint16, protocol uint8, allow bool) error
	ShowIPPortRules           func(limit int, search string)
	ShowWhitelist             func(limit int, search string)
	ShowLockList              func(limit int, search string)
	ImportLockListFromFile    func(filename string)
	ImportWhitelistFromFile   func(filename string)
	ImportIPPortRulesFromFile func(filename string)
	ClearBlacklist            func()
)

// Security commands
// 安全命令
var (
	SyncDropFragments   func(enable bool)
	SyncStrictTCP       func(enable bool)
	SyncSYNLimit        func(enable bool)
	SyncBogonFilter     func(enable bool)
	SyncAutoBlock       func(enable bool)
	SyncAutoBlockExpiry func(seconds uint32)
)

// Limit commands
// 限速命令
var (
	SyncRateLimitRule  func(ip string, rate uint64, burst uint64, add bool)
	ShowRateLimitRules func()
)

// Port commands
// 端口命令
var (
	SyncAllowedPort func(port uint16, add bool)
)

// Web commands
// Web 命令
var (
	RunWebServer func(port int)
)

// Conntrack commands
// 连接跟踪命令
var (
	ShowConntrack func()
)

// Quick commands
// 快速命令
var (
	AskConfirmation func(prompt string) bool
)
