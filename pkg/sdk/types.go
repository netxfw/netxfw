package sdk

import "github.com/netxfw/netxfw/internal/plugins/types"

// NOTE: Batch P0_1 bridging type.
// This file intentionally exists to move pkg/sdk off internal/plugins/types imports
// without breaking the rest of the repository in one shot.
//
// Next step after P0_1: move the actual GlobalConfig definition out of
// internal/plugins/types and delete this alias.

type GlobalConfig = types.GlobalConfig
