package xdp

import (
	sdk "github.com/netxfw/netxfw/pkg/sdk"
)

// ManagerInterface is now a type alias to sdk.ManagerInterface to avoid circular dependencies.
// ManagerInterface 现在是 sdk.ManagerInterface 的类型别名，以避免循环依赖。
//
// Phase 3 mapping: new datapath-facing contracts should be declared under
// internal/datapath/xdp and only re-exported here when a backend bridge is needed.
type ManagerInterface = sdk.ManagerInterface
