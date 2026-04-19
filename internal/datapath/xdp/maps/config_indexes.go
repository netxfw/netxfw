package maps

// Global config map indexes exposed through the datapath maps facade.
const (
	ConfigIndexDefaultDeny        = 0
	ConfigIndexAllowReturnTraffic = 1
	ConfigIndexAllowICMP          = 2
	ConfigIndexEnableConntrack    = 3
	ConfigIndexConntrackTimeout   = 4
	ConfigIndexICMPRate           = 5
	ConfigIndexICMPBurst          = 6
	ConfigIndexEnableAFXDP        = 7
	ConfigIndexStrictProto        = 9
	ConfigIndexEnableRateLimit    = 10
	ConfigIndexDropFragments      = 11
	ConfigIndexStrictTCP          = 12
	ConfigIndexSYNLimit           = 13
	ConfigIndexBogonFilter        = 14
	ConfigIndexAutoBlock          = 15
	ConfigIndexAutoBlockExpiry    = 16
)
