// Package errors provides errors functionality.
package errors

import "fmt"

// Code defines stable domain error codes used across application services.
type Code string

const (
	CodeInvalidInput   Code = "invalid_input"
	CodeNotFound       Code = "not_found"
	CodeConflict       Code = "conflict"
	CodePermission     Code = "permission_denied"
	CodeInternal       Code = "internal_error"
	CodeUnavailable    Code = "unavailable"
	CodeNotImplemented Code = "not_implemented"
)

// DomainError is the canonical error shape for V2 service boundaries.
type DomainError struct {
	Code    Code
	Message string
	Cause   error
}

func (e *DomainError) Error() string {
	if e == nil {
		return ""
	}
	if e.Cause == nil {
		return fmt.Sprintf("%s: %s", e.Code, e.Message)
	}
	return fmt.Sprintf("%s: %s: %v", e.Code, e.Message, e.Cause)
}

func (e *DomainError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// Wrap converts an internal error into a typed domain error.
func Wrap(code Code, msg string, err error) error {
	if err == nil {
		return nil
	}
	return &DomainError{
		Code:    code,
		Message: msg,
		Cause:   err,
	}
}
