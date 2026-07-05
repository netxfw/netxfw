package config

import (
	sdk "github.com/netxfw/netxfw/pkg/sdk"
	"github.com/netxfw/netxfw/internal/utils/logger"
)

// RuntimeServicesConfig is an alias for the SDK type.
type RuntimeServicesConfig = sdk.RuntimeServicesConfig

// Config is an alias for the SDK GlobalConfig — the single source of truth.
type Config = sdk.GlobalConfig

// LoggingConfig is re-exported from logger (which itself aliases sdk.LoggingConfig).
type LoggingConfig = logger.LoggingConfig
