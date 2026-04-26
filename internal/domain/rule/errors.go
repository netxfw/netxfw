// Package rule provides rule functionality.
package rule

import "errors"

var (
	ErrEmptyTTL       = errors.New("empty ttl")
	ErrInvalidIP      = errors.New("invalid IP address format")
	ErrInvalidAction  = errors.New("invalid rule action")
	ErrInvalidPort    = errors.New("invalid port")
	ErrInvalidTTL     = errors.New("invalid ttl")
	ErrDuplicateRule  = errors.New("duplicate rule")
	ErrMissingCIDR    = errors.New("missing cidr")
	ErrSelectorFormat = errors.New("invalid selector format")
)
