package errors

import (
	"errors"
	"testing"

	domainerrors "github.com/netxfw/netxfw/internal/domain/errors"
	sdkerrors "github.com/netxfw/netxfw/pkg/errors"
)

func TestUnifiedError(t *testing.T) {
	cause := errors.New("underlying error")
	err := New(ErrCodeInvalidIP, "invalid IP address", cause)

	if err.Code != ErrCodeInvalidIP {
		t.Errorf("expected code %s, got %s", ErrCodeInvalidIP, err.Code)
	}

	if err.Message != "invalid IP address" {
		t.Errorf("expected message 'invalid IP address', got '%s'", err.Message)
	}

	if err.Cause != cause {
		t.Errorf("expected cause to be underlying error")
	}

	expectedError := "[INVALID_IP] invalid IP address: underlying error"
	if err.Error() != expectedError {
		t.Errorf("expected error string '%s', got '%s'", expectedError, err.Error())
	}

	unwrapped := err.Unwrap()
	if unwrapped != cause {
		t.Errorf("expected unwrap to return cause")
	}
}

func TestUnifiedErrorWithContext(t *testing.T) {
	ctx := map[string]interface{}{
		"ip":        "192.168.1.1",
		"operation": "block",
	}
	err := NewWithContext(ErrCodeMapOperation, "failed to block IP", nil, ctx)

	if err.Context["ip"] != "192.168.1.1" {
		t.Errorf("expected context ip to be '192.168.1.1'")
	}

	if err.Context["operation"] != "block" {
		t.Errorf("expected context operation to be 'block'")
	}
}

func TestWrap(t *testing.T) {
	cause := errors.New("underlying error")
	err := Wrap(cause, ErrCodeInvalidInput, "invalid input")

	var unifiedErr *UnifiedError
	if !errors.As(err, &unifiedErr) {
		t.Errorf("expected to unwrap to UnifiedError")
	}

	if unifiedErr.Code != ErrCodeInvalidInput {
		t.Errorf("expected code %s, got %s", ErrCodeInvalidInput, unifiedErr.Code)
	}
}

func TestToDomainError(t *testing.T) {
	t.Run("from UnifiedError", func(t *testing.T) {
		err := New(ErrCodeInvalidIP, "invalid IP", nil)
		domainErr := ToDomainError(err)

		if domainErr.Code != domainerrors.Code(ErrCodeInvalidIP) {
			t.Errorf("expected domain code %s, got %s", ErrCodeInvalidIP, domainErr.Code)
		}
	})

	t.Run("from XDPError", func(t *testing.T) {
		xdpErr := sdkerrors.NewXDPError(sdkerrors.ErrInvalidIP, "invalid IP", &sdkerrors.Context{
			IP: "192.168.1.1",
		}, nil)
		domainErr := ToDomainError(xdpErr)

		if domainErr.Code != domainerrors.CodeInvalidInput {
			t.Errorf("expected domain code %s, got %s", domainerrors.CodeInvalidInput, domainErr.Code)
		}
	})

	t.Run("from DomainError", func(t *testing.T) {
		originalErr := &domainerrors.DomainError{
			Code:    domainerrors.CodeNotFound,
			Message: "not found",
		}
		domainErr := ToDomainError(originalErr)

		if domainErr != originalErr {
			t.Errorf("expected same domain error instance")
		}
	})

	t.Run("from generic error", func(t *testing.T) {
		genericErr := errors.New("generic error")
		domainErr := ToDomainError(genericErr)

		if domainErr.Code != domainerrors.CodeInternal {
			t.Errorf("expected domain code %s, got %s", domainerrors.CodeInternal, domainErr.Code)
		}
	})
}

func TestToSDKError(t *testing.T) {
	t.Run("from UnifiedError", func(t *testing.T) {
		ctx := map[string]interface{}{
			"ip":        "192.168.1.1",
			"operation": "block",
		}
		err := NewWithContext(ErrCodeMapOperation, "failed to block IP", nil, ctx)
		xdpErr := ToSDKError(err)

		if xdpErr == nil {
			t.Fatalf("expected non-nil XDPError")
		}

		if xdpErr.Context == nil {
			t.Errorf("expected non-nil context")
		} else {
			if xdpErr.Context.IP != "192.168.1.1" {
				t.Errorf("expected context ip to be '192.168.1.1', got '%s'", xdpErr.Context.IP)
			}
			if xdpErr.Context.Operation != "block" {
				t.Errorf("expected context operation to be 'block', got '%s'", xdpErr.Context.Operation)
			}
		}
	})

	t.Run("from XDPError", func(t *testing.T) {
		originalErr := sdkerrors.NewXDPError(sdkerrors.ErrInvalidIP, "invalid IP", nil, nil)
		xdpErr := ToSDKError(originalErr)

		if xdpErr != originalErr {
			t.Errorf("expected same XDPError instance")
		}
	})

	t.Run("from DomainError", func(t *testing.T) {
		domainErr := &domainerrors.DomainError{
			Code:    domainerrors.CodeInvalidInput,
			Message: "invalid input",
		}
		xdpErr := ToSDKError(domainErr)

		if xdpErr == nil {
			t.Fatalf("expected non-nil XDPError")
		}

		if xdpErr.Message != "invalid input" {
			t.Errorf("expected message 'invalid input', got '%s'", xdpErr.Message)
		}
	})
}

func TestGetErrorCode(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected ErrorCode
	}{
		{
			name:     "UnifiedError",
			err:      New(ErrCodeInvalidIP, "invalid IP", nil),
			expected: ErrCodeInvalidIP,
		},
		{
			name:     "DomainError",
			err:      &domainerrors.DomainError{Code: domainerrors.CodeNotFound},
			expected: ErrCodeNotFound,
		},
		{
			name:     "XDPError with ErrInvalidIP",
			err:      sdkerrors.NewXDPError(sdkerrors.ErrInvalidIP, "invalid IP", nil, nil),
			expected: ErrCodeInvalidIP,
		},
		{
			name:     "XDPError with ErrMapNotFound",
			err:      sdkerrors.NewXDPError(sdkerrors.ErrMapNotFound, "map not found", nil, nil),
			expected: ErrCodeNotFound,
		},
		{
			name:     "generic error",
			err:      errors.New("generic error"),
			expected: ErrCodeInternal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code := GetErrorCode(tt.err)
			if code != tt.expected {
				t.Errorf("expected code %s, got %s", tt.expected, code)
			}
		})
	}
}

func TestIsErrorCode(t *testing.T) {
	err := New(ErrCodeInvalidIP, "invalid IP", nil)

	if !IsErrorCode(err, ErrCodeInvalidIP) {
		t.Errorf("expected IsErrorCode to return true")
	}

	if IsErrorCode(err, ErrCodeNotFound) {
		t.Errorf("expected IsErrorCode to return false for different code")
	}
}

func TestHelperFunctions(t *testing.T) {
	t.Run("IsInvalidInput", func(t *testing.T) {
		tests := []struct {
			err      error
			expected bool
		}{
			{New(ErrCodeInvalidInput, "invalid input", nil), true},
			{New(ErrCodeInvalidIP, "invalid IP", nil), true},
			{New(ErrCodeInvalidCIDR, "invalid CIDR", nil), true},
			{New(ErrCodeInvalidPort, "invalid port", nil), true},
			{New(ErrCodeNotFound, "not found", nil), false},
		}

		for _, tt := range tests {
			result := IsInvalidInput(tt.err)
			if result != tt.expected {
				t.Errorf("IsInvalidInput(%v) = %v, expected %v", tt.err, result, tt.expected)
			}
		}
	})

	t.Run("IsNotFound", func(t *testing.T) {
		err := New(ErrCodeNotFound, "not found", nil)
		if !IsNotFound(err) {
			t.Errorf("expected IsNotFound to return true")
		}
	})

	t.Run("IsPermissionDenied", func(t *testing.T) {
		err := New(ErrCodePermission, "permission denied", nil)
		if !IsPermissionDenied(err) {
			t.Errorf("expected IsPermissionDenied to return true")
		}
	})

	t.Run("IsTimeout", func(t *testing.T) {
		err := New(ErrCodeTimeout, "timeout", nil)
		if !IsTimeout(err) {
			t.Errorf("expected IsTimeout to return true")
		}
	})
}

func TestErrorChaining(t *testing.T) {
	cause := errors.New("root cause")
	unifiedErr := New(ErrCodeMapOperation, "map operation failed", cause)

	domainErr := ToDomainError(unifiedErr)
	if domainErr.Cause != cause {
		t.Errorf("expected domain error cause to be preserved")
	}

	xdpErr := ToSDKError(unifiedErr)
	if xdpErr.Cause != cause {
		t.Errorf("expected XDP error cause to be preserved")
	}
}
