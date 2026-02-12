package common

// System commands
var (
	InitConfiguration   func()
	ShowStatus          func()
	TestConfiguration   func()
	RunDaemon           func()
	InstallXDP          func()
	ReloadXDP           func()
	RemoveXDP           func()
	SyncDefaultDeny     func(enable bool)
	SyncEnableRateLimit func(enable bool)
	SyncEnableAFXDP     func(enable bool)
)

// Rule commands
var (
	EnsureStandaloneMode      func()
	SyncLockMap               func(ip string, lock bool)
	SyncWhitelistMap          func(ip string, port uint16, allow bool)
	SyncIPPortRule            func(ip string, port uint16, protocol uint8, allow bool)
	ShowIPPortRules           func(limit int, search string)
	ShowWhitelist             func(limit int, search string)
	ShowLockList              func(limit int, search string)
	ImportLockListFromFile    func(filename string)
	ImportWhitelistFromFile   func(filename string)
	ImportIPPortRulesFromFile func(filename string)
	ClearBlacklist            func()
)

// Security commands
var (
	SyncDropFragments   func(enable bool)
	SyncStrictTCP       func(enable bool)
	SyncSYNLimit        func(enable bool)
	SyncBogonFilter     func(enable bool)
	SyncAutoBlock       func(enable bool)
	SyncAutoBlockExpiry func(seconds uint32)
)

// Limit commands
var (
	SyncRateLimitRule  func(ip string, rate uint64, burst uint64, add bool)
	ShowRateLimitRules func()
)

// Port commands
var (
	SyncAllowedPort func(port uint16, add bool)
)

// Web commands
var (
	RunWebServer func(port int)
)

// Conntrack commands
var (
	ShowConntrack func()
)

// Quick commands
var (
	AskConfirmation func(prompt string) bool
)
