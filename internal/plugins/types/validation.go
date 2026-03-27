package types

import "github.com/netxfw/netxfw/pkg/sdk"

// Validation methods for configuration types now live on the canonical
// definitions in pkg/sdk. This file remains to preserve package layout.

func validateCIDR(s string) error {
	return sdk.ValidateCIDROrIPForConfig(s)
}
