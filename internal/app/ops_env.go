package app

import (
	"github.com/netxfw/netxfw/internal/runtime"
)

// GetRuntimeMode returns the active runtime mode.
func GetRuntimeMode() string {
	return runtime.Mode
}

// SetRuntimeMode sets the active runtime mode.
func SetRuntimeMode(mode string) {
	runtime.Mode = mode
}

// RuntimeModeVar returns a pointer to the runtime mode string for flag binding.
func RuntimeModeVar() *string {
	return &runtime.Mode
}

// IsTestMode reports whether the current runtime mode is test.
func IsTestMode() bool {
	return runtime.Mode == "test"
}

// GetPinPath returns the active BPF pin path.
func GetPinPath() string {
	return runtime.GetPinPath()
}
