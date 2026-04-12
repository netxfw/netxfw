package xdp

import (
	"errors"
)

// XDP-specific errors.
// XDP 特定错误。
var (
	ErrBPFLoadFailed      = errors.New("BPF program load failed")
	ErrBPFAttachFailed    = errors.New("BPF program attach failed")
	ErrBPFDetachFailed    = errors.New("BPF program detach failed")
	ErrNotInitialized     = errors.New("manager not initialized")
	ErrAlreadyInitialized = errors.New("manager already initialized")
)

// Common errors re-exported from pkg/errors for convenience.
// 为了方便，从 pkg/errors 重新导出的通用错误。
var (
	ErrMapNotAvailable   = errors.New("map not available")
	ErrInvalidIP         = errors.New("invalid IP address")
	ErrInvalidCIDR       = errors.New("invalid CIDR")
	ErrInvalidPort       = errors.New("invalid port")
	ErrKeyNotFound       = errors.New("key does not exist")
	ErrMapUpdateFailed   = errors.New("map update failed")
	ErrMapDeleteFailed   = errors.New("map delete failed")
	ErrMapIterateFailed  = errors.New("map iteration failed")
	ErrConfigNotFound    = errors.New("config not found")
	ErrInvalidConfig     = errors.New("invalid configuration")
	ErrPermissionDenied  = errors.New("permission denied")
	ErrResourceExhausted = errors.New("resource exhausted")
	ErrTimeout           = errors.New("operation timeout")
)
