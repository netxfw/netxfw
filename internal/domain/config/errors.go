package config

import "errors"

var (
	ErrInvalidConfig = errors.New("invalid config")
	ErrNilConfig     = errors.New("nil config")
)
