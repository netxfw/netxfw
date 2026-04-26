// Package errors provides errors functionality.
package errors

import (
	"errors"
	"fmt"
	"strings"
)

var (
	ErrInvalidIP            = errors.New("invalid IP address")
	ErrInvalidCIDR          = errors.New("invalid CIDR notation")
	ErrInvalidPort          = errors.New("invalid port number")
	ErrInvalidTTL           = errors.New("invalid TTL value")
	ErrInvalidRate          = errors.New("invalid rate limit value")
	ErrInvalidBurst         = errors.New("invalid burst value")
	ErrInvalidAction        = errors.New("invalid action")
	ErrInvalidProtocol      = errors.New("invalid protocol")
	ErrInvalidFilePath      = errors.New("invalid file path")
	ErrFileNotFound         = errors.New("file not found")
	ErrFileTooLarge         = errors.New("file too large")
	ErrPermissionDenied     = errors.New("permission denied")
	ErrConfigNotFound       = errors.New("config not found")
	ErrConfigInvalid        = errors.New("invalid configuration")
	ErrMapNotFound          = errors.New("BPF map not found")
	ErrMapOperationFailed   = errors.New("BPF map operation failed")
	ErrXDPLoadFailed        = errors.New("XDP program load failed")
	ErrXDPAttachFailed      = errors.New("XDP program attach failed")
	ErrDaemonNotRunning     = errors.New("daemon not running")
	ErrDaemonAlreadyRunning = errors.New("daemon already running")
	ErrTimeout              = errors.New("operation timeout")
	ErrCanceled             = errors.New("operation canceled")
	ErrNotImplemented       = errors.New("not implemented")
)

type Context struct {
	Operation string
	MapName   string
	IP        string
	Port      int
	CIDR      string
	Key       string
	Value     interface{}
	Extra     map[string]interface{}
}

type XDPError struct {
	Base    error
	Message string
	Context *Context
	Cause   error
}

func (e *XDPError) Error() string {
	var sb strings.Builder
	sb.WriteString(e.Message)
	if e.Context != nil {
		sb.WriteString(" [")
		if e.Context.Operation != "" {
			sb.WriteString("op=")
			sb.WriteString(e.Context.Operation)
		}
		if e.Context.MapName != "" {
			sb.WriteString(" map=")
			sb.WriteString(e.Context.MapName)
		}
		if e.Context.IP != "" {
			sb.WriteString(" ip=")
			sb.WriteString(e.Context.IP)
		}
		if e.Context.CIDR != "" {
			sb.WriteString(" cidr=")
			sb.WriteString(e.Context.CIDR)
		}
		if e.Context.Port > 0 {
			sb.WriteString(" port=")
			fmt.Fprintf(&sb, "%d", e.Context.Port)
		}
		if e.Context.Key != "" {
			sb.WriteString(" key=")
			sb.WriteString(e.Context.Key)
		}
		if e.Context.Value != nil {
			sb.WriteString(" value=")
			fmt.Fprintf(&sb, "%v", e.Context.Value)
		}
		sb.WriteString("]")
	}
	if e.Cause != nil {
		sb.WriteString(": ")
		sb.WriteString(e.Cause.Error())
	}
	return sb.String()
}

func (e *XDPError) Unwrap() error {
	if e.Base != nil {
		return e.Base
	}
	return e.Cause
}

func NewXDPError(base error, message string, ctx *Context, cause error) *XDPError {
	return &XDPError{
		Base:    base,
		Message: message,
		Context: ctx,
		Cause:   cause,
	}
}

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

func NewMapUpdateError(mapName, key string, cause error) *XDPError {
	return NewXDPError(ErrMapOperationFailed, "map update failed", &Context{
		Operation: "update",
		MapName:   mapName,
		Key:       key,
	}, cause)
}

func NewMapDeleteError(mapName, key string, cause error) *XDPError {
	return NewXDPError(ErrMapOperationFailed, "map delete failed", &Context{
		Operation: "delete",
		MapName:   mapName,
		Key:       key,
	}, cause)
}

func NewMapLookupError(mapName, key string, cause error) *XDPError {
	return NewXDPError(ErrMapOperationFailed, "map lookup failed", &Context{
		Operation: "lookup",
		MapName:   mapName,
		Key:       key,
	}, cause)
}

func NewBlockIPError(ip string, cause error) *XDPError {
	return NewXDPError(ErrMapOperationFailed, "failed to block IP", &Context{
		Operation: "block",
		IP:        ip,
	}, cause)
}

func NewUnblockIPError(ip string, cause error) *XDPError {
	return NewXDPError(ErrMapOperationFailed, "failed to unblock IP", &Context{
		Operation: "unblock",
		IP:        ip,
	}, cause)
}

func NewAllowIPError(cidr string, port int, cause error) *XDPError {
	return NewXDPError(ErrMapOperationFailed, "failed to allow IP", &Context{
		Operation: "allow",
		CIDR:      cidr,
		Port:      port,
	}, cause)
}

func NewRateLimitError(cidr string, rate, burst uint64, cause error) *XDPError {
	return NewXDPError(ErrMapOperationFailed, "failed to set rate limit", &Context{
		Operation: "ratelimit",
		CIDR:      cidr,
		Extra:     map[string]interface{}{"rate": rate, "burst": burst},
	}, cause)
}

func IsXDPError(err error) bool {
	var xdpe *XDPError
	return errors.As(err, &xdpe)
}

func GetErrorContext(err error) *Context {
	var xdpe *XDPError
	if errors.As(err, &xdpe) {
		return xdpe.Context
	}
	return nil
}
