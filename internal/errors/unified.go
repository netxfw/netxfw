package errors

import (
	"errors"
	"fmt"

	domainerrors "github.com/netxfw/netxfw/internal/domain/errors"
	sdkerrors "github.com/netxfw/netxfw/pkg/errors"
)

type ErrorCode string

const (
	ErrCodeInvalidInput   ErrorCode = "INVALID_INPUT"
	ErrCodeNotFound       ErrorCode = "NOT_FOUND"
	ErrCodeConflict       ErrorCode = "CONFLICT"
	ErrCodePermission     ErrorCode = "PERMISSION_DENIED"
	ErrCodeInternal       ErrorCode = "INTERNAL_ERROR"
	ErrCodeUnavailable    ErrorCode = "UNAVAILABLE"
	ErrCodeNotImplemented ErrorCode = "NOT_IMPLEMENTED"
	ErrCodeInvalidIP      ErrorCode = "INVALID_IP"
	ErrCodeInvalidCIDR    ErrorCode = "INVALID_CIDR"
	ErrCodeInvalidPort    ErrorCode = "INVALID_PORT"
	ErrCodeMapOperation   ErrorCode = "MAP_OPERATION_FAILED"
	ErrCodeXDPLoad        ErrorCode = "XDP_LOAD_FAILED"
	ErrCodeXDPAttach      ErrorCode = "XDP_ATTACH_FAILED"
	ErrCodeConfig         ErrorCode = "CONFIG_ERROR"
	ErrCodeTimeout        ErrorCode = "TIMEOUT"
	ErrCodeCanceled       ErrorCode = "CANCELED"
)

type UnifiedError struct {
	Code    ErrorCode
	Message string
	Cause   error
	Context map[string]interface{}
}

func (e *UnifiedError) Error() string {
	if e == nil {
		return ""
	}
	msg := fmt.Sprintf("[%s] %s", e.Code, e.Message)
	if e.Cause != nil {
		msg += fmt.Sprintf(": %v", e.Cause)
	}
	return msg
}

func (e *UnifiedError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

func New(code ErrorCode, message string, cause error) *UnifiedError {
	return &UnifiedError{
		Code:    code,
		Message: message,
		Cause:   cause,
	}
}

func NewWithContext(code ErrorCode, message string, cause error, ctx map[string]interface{}) *UnifiedError {
	return &UnifiedError{
		Code:    code,
		Message: message,
		Cause:   cause,
		Context: ctx,
	}
}

func Wrap(err error, code ErrorCode, message string) error {
	if err == nil {
		return nil
	}
	return New(code, message, err)
}

func ToDomainError(err error) *domainerrors.DomainError {
	if err == nil {
		return nil
	}

	var domainErr *domainerrors.DomainError
	if errors.As(err, &domainErr) {
		return domainErr
	}

	var unifiedErr *UnifiedError
	if errors.As(err, &unifiedErr) {
		return &domainerrors.DomainError{
			Code:    domainerrors.Code(unifiedErr.Code),
			Message: unifiedErr.Message,
			Cause:   unifiedErr.Cause,
		}
	}

	var xdpErr *sdkerrors.XDPError
	if errors.As(err, &xdpErr) {
		code := mapXDPErrorToCode(xdpErr)
		return &domainerrors.DomainError{
			Code:    code,
			Message: xdpErr.Message,
			Cause:   xdpErr.Cause,
		}
	}

	return &domainerrors.DomainError{
		Code:    domainerrors.CodeInternal,
		Message: err.Error(),
		Cause:   err,
	}
}

func ToSDKError(err error) *sdkerrors.XDPError {
	if err == nil {
		return nil
	}

	var xdpErr *sdkerrors.XDPError
	if errors.As(err, &xdpErr) {
		return xdpErr
	}

	var unifiedErr *UnifiedError
	if errors.As(err, &unifiedErr) {
		ctx := &sdkerrors.Context{}
		if unifiedErr.Context != nil {
			if op, ok := unifiedErr.Context["operation"].(string); ok {
				ctx.Operation = op
			}
			if ip, ok := unifiedErr.Context["ip"].(string); ok {
				ctx.IP = ip
			}
			if cidr, ok := unifiedErr.Context["cidr"].(string); ok {
				ctx.CIDR = cidr
			}
			if port, ok := unifiedErr.Context["port"].(int); ok {
				ctx.Port = port
			}
			if mapName, ok := unifiedErr.Context["map"].(string); ok {
				ctx.MapName = mapName
			}
		}
		return sdkerrors.NewXDPError(mapCodeToSDKError(domainerrors.Code(unifiedErr.Code)), unifiedErr.Message, ctx, unifiedErr.Cause)
	}

	var domainErr *domainerrors.DomainError
	if errors.As(err, &domainErr) {
		return &sdkerrors.XDPError{
			Base:    mapCodeToSDKError(domainerrors.Code(domainErr.Code)),
			Message: domainErr.Message,
			Cause:   domainErr.Cause,
		}
	}

	return &sdkerrors.XDPError{
		Base:    sdkerrors.ErrInvalidIP,
		Message: err.Error(),
		Cause:   err,
	}
}

func mapXDPErrorToCode(xdpErr *sdkerrors.XDPError) domainerrors.Code {
	if xdpErr.Base == nil {
		return domainerrors.CodeInternal
	}

	switch xdpErr.Base {
	case sdkerrors.ErrInvalidIP, sdkerrors.ErrInvalidCIDR, sdkerrors.ErrInvalidPort:
		return domainerrors.CodeInvalidInput
	case sdkerrors.ErrMapNotFound, sdkerrors.ErrFileNotFound, sdkerrors.ErrConfigNotFound:
		return domainerrors.CodeNotFound
	case sdkerrors.ErrPermissionDenied:
		return domainerrors.CodePermission
	case sdkerrors.ErrMapOperationFailed:
		return domainerrors.CodeInternal
	case sdkerrors.ErrTimeout:
		return domainerrors.CodeUnavailable
	default:
		return domainerrors.CodeInternal
	}
}

func mapCodeToSDKError(code domainerrors.Code) error {
	switch code {
	case domainerrors.CodeInvalidInput:
		return sdkerrors.ErrInvalidIP
	case domainerrors.CodeNotFound:
		return sdkerrors.ErrMapNotFound
	case domainerrors.CodePermission:
		return sdkerrors.ErrPermissionDenied
	case domainerrors.CodeUnavailable:
		return sdkerrors.ErrTimeout
	default:
		return sdkerrors.ErrInvalidIP
	}
}

func GetErrorCode(err error) ErrorCode {
	if err == nil {
		return ""
	}

	var unifiedErr *UnifiedError
	if errors.As(err, &unifiedErr) {
		return unifiedErr.Code
	}

	var domainErr *domainerrors.DomainError
	if errors.As(err, &domainErr) {
		return mapDomainCodeToErrorCode(domainErr.Code)
	}

	var xdpErr *sdkerrors.XDPError
	if errors.As(err, &xdpErr) {
		return mapXDPErrorToErrorCode(xdpErr)
	}

	return ErrCodeInternal
}

func mapDomainCodeToErrorCode(code domainerrors.Code) ErrorCode {
	switch code {
	case domainerrors.CodeInvalidInput:
		return ErrCodeInvalidInput
	case domainerrors.CodeNotFound:
		return ErrCodeNotFound
	case domainerrors.CodeConflict:
		return ErrCodeConflict
	case domainerrors.CodePermission:
		return ErrCodePermission
	case domainerrors.CodeInternal:
		return ErrCodeInternal
	case domainerrors.CodeUnavailable:
		return ErrCodeUnavailable
	case domainerrors.CodeNotImplemented:
		return ErrCodeNotImplemented
	default:
		return ErrCodeInternal
	}
}

func mapXDPErrorToErrorCode(xdpErr *sdkerrors.XDPError) ErrorCode {
	if xdpErr.Base == nil {
		return ErrCodeInternal
	}

	switch xdpErr.Base {
	case sdkerrors.ErrInvalidIP:
		return ErrCodeInvalidIP
	case sdkerrors.ErrInvalidCIDR:
		return ErrCodeInvalidCIDR
	case sdkerrors.ErrInvalidPort:
		return ErrCodeInvalidPort
	case sdkerrors.ErrMapNotFound:
		return ErrCodeNotFound
	case sdkerrors.ErrMapOperationFailed:
		return ErrCodeMapOperation
	case sdkerrors.ErrXDPLoadFailed:
		return ErrCodeXDPLoad
	case sdkerrors.ErrXDPAttachFailed:
		return ErrCodeXDPAttach
	case sdkerrors.ErrConfigInvalid, sdkerrors.ErrConfigNotFound:
		return ErrCodeConfig
	case sdkerrors.ErrTimeout:
		return ErrCodeTimeout
	case sdkerrors.ErrCanceled:
		return ErrCodeCanceled
	default:
		return ErrCodeInternal
	}
}

func IsErrorCode(err error, code ErrorCode) bool {
	return GetErrorCode(err) == code
}

func IsInvalidInput(err error) bool {
	return IsErrorCode(err, ErrCodeInvalidInput) || IsErrorCode(err, ErrCodeInvalidIP) || IsErrorCode(err, ErrCodeInvalidCIDR) || IsErrorCode(err, ErrCodeInvalidPort)
}

func IsNotFound(err error) bool {
	return IsErrorCode(err, ErrCodeNotFound)
}

func IsPermissionDenied(err error) bool {
	return IsErrorCode(err, ErrCodePermission)
}

func IsTimeout(err error) bool {
	return IsErrorCode(err, ErrCodeTimeout)
}
