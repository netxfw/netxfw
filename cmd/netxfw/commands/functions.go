package commands

// Shared function variables for main package to assign
var (
	EnsureStandaloneMode func()
	AskConfirmation      func(string) bool

	// System commands
	InitConfiguration   func()
	ShowStatus          func()
	TestConfiguration   func()
	RunDaemon           func()
	InstallXDP          func()
	ReloadXDP           func()
	RemoveXDP           func()
	SyncDefaultDeny     func(bool)
	SyncEnableRateLimit func(bool)
	SyncEnableAFXDP     func(bool)

	// Rule commands
	SyncLockMap               func(string, bool)
	SyncWhitelistMap          func(string, uint16, bool)
	SyncIPPortRule            func(string, uint16, uint8, bool)
	ShowIPPortRules           func(int, string)
	ShowWhitelist             func(int, string)
	ShowLockList              func(int, string)
	ImportLockListFromFile    func(string)
	ImportWhitelistFromFile   func(string)
	ImportIPPortRulesFromFile func(string)
	ClearBlacklist            func()

	// Security commands
	SyncDropFragments   func(bool)
	SyncStrictTCP       func(bool)
	SyncSYNLimit        func(bool)
	SyncBogonFilter     func(bool)
	SyncAutoBlock       func(bool)
	SyncAutoBlockExpiry func(uint32)

	// Limit commands
	SyncRateLimitRule  func(string, uint64, uint64, bool)
	ShowRateLimitRules func()

	// Port commands
	SyncAllowedPort func(uint16, bool)

	// Web commands
	RunWebServer func(int)

	// Conntrack commands
	ShowConntrack func()
)
