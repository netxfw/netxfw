package errors

import (
	"errors"
	"fmt"
)

var (
	ErrInvalidIP           = errors.New("invalid IP address")
	ErrInvalidCIDR         = errors.New("invalid CIDR notation")
	ErrInvalidPort         = errors.New("invalid port number")
	ErrInvalidTTL          = errors.New("invalid TTL value")
	ErrInvalidRate         = errors.New("invalid rate limit value")
	ErrInvalidBurst        = errors.New("invalid burst value")
	ErrInvalidAction       = errors.New("invalid action")
	ErrInvalidProtocol     = errors.New("invalid protocol")
	ErrInvalidFilePath     = errors.New("invalid file path")
	ErrFileNotFound        = errors.New("file not found")
	ErrFileTooLarge        = errors.New("file too large")
	ErrPermissionDenied    = errors.New("permission denied")
	ErrConfigNotFound      = errors.New("config not found")
	ErrConfigInvalid       = errors.New("invalid configuration")
	ErrMapNotFound         = errors.New("BPF map not found")
	ErrMapOperationFailed  = errors.New("BPF map operation failed")
	ErrXDPLoadFailed       = errors.New("XDP program load failed")
	ErrXDPAttachFailed     = errors.New("XDP program attach failed")
	ErrDaemonNotRunning    = errors.New("daemon not running")
	ErrDaemonAlreadyRunning = errors.New("daemon already running")
	ErrTimeout             = errors.New("operation timeout")
	ErrCanceled            = errors.New("operation canceled")
	ErrNotImplemented      = errors.New("not implemented")
)

func NewIPError(ip string) error {
	return fmt.Errorf("%w: %s", ErrInvalidIP, ip)
}

func NewCIDRError(cidr string) error {
	return fmt.Errorf("%w: %s", ErrInvalidCIDR, cidr)
}

func NewPortError(port int) error {
	return fmt.Errorf("%w: %d", ErrInvalidPort, port)
}

func NewTTLError(ttl string) error {
	return fmt.Errorf("%w: %s", ErrInvalidTTL, ttl)
}

func NewMapError(mapName string, op string, err error) error {
	return fmt.Errorf("%w: map=%s op=%s: %v", ErrMapOperationFailed, mapName, op, err)
}

func NewFileError(path string, reason error) error {
	return fmt.Errorf("%w: %s: %v", ErrFileNotFound, path, reason)
}

func NewConfigError(field string, value interface{}) error {
	return fmt.Errorf("%w: field=%s value=%v", ErrConfigInvalid, field, value)
}
