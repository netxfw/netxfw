package config

import sdk "github.com/netxfw/netxfw/pkg/sdk"

// Type aliases for SDK types — domain/config uses the SDK types as the single
// source of truth, eliminating the need for ConfigToSDK/ConfigFromSDK conversion.
type ClusterConfig = sdk.ClusterConfig
type BaseConfig = sdk.BaseConfig
type ModuleConfig = sdk.ModuleConfig
