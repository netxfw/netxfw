package config

import (
	"errors"
	"fmt"
)

// Validate returns the canonical config validation error for main-path callers.
func Validate(cfg *Config) error {
	if cfg == nil {
		return ErrNilConfig
	}
	validator := NewConfigValidator()
	if err := validator.Normalize(cfg); err != nil {
		return err
	}
	if err := validator.ValidateErr(cfg); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidConfig, err)
	}
	return nil
}

// IsValidationError reports whether err is a config validation failure.
func IsValidationError(err error) bool {
	return errors.Is(err, ErrInvalidConfig) || errors.Is(err, ErrNilConfig)
}
