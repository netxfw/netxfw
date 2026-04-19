package rule

import (
	"fmt"
	"time"

	"github.com/netxfw/netxfw/internal/utils/iputil"
)

const (
	MinPort       = 0
	MaxPort       = 65535
	MinTTLSeconds = 1
	MaxTTLSeconds = 365 * 24 * 60 * 60
	MaxRate       = 1000000
	MaxBurst      = 10000000
)

func ValidateIP(ip string) error {
	if iputil.IsValidIP(ip) || iputil.IsValidCIDR(ip) {
		return nil
	}
	return fmt.Errorf("%w: invalid IP address format: %s", ErrInvalidIP, ip)
}

func ValidatePort(port int, allowZero bool) error {
	minPort := 1
	if allowZero {
		minPort = MinPort
	}
	if port < minPort || port > MaxPort {
		if allowZero {
			return fmt.Errorf("%w: port must be between %d-%d, got %d", ErrInvalidPort, MinPort, MaxPort, port)
		}
		return fmt.Errorf("%w: port must be between 1-%d, got %d", ErrInvalidPort, MaxPort, port)
	}
	return nil
}

func IsValidPort(port int) bool {
	return port >= MinPort && port <= MaxPort
}

func ValidateRateLimit(rate, burst uint64) error {
	if rate == 0 {
		return fmt.Errorf("rate cannot be 0")
	}
	if rate > MaxRate {
		return fmt.Errorf("rate must be at most %d, got %d", MaxRate, rate)
	}
	if burst == 0 {
		return fmt.Errorf("burst cannot be 0")
	}
	if burst > MaxBurst {
		return fmt.Errorf("burst must be at most %d, got %d", MaxBurst, burst)
	}
	return nil
}

func ParseTTL(ttlStr string) (time.Duration, error) {
	if ttlStr == "" {
		return 0, fmt.Errorf("%w: TTL flag is required (e.g., --ttl 1h, --ttl 24h, --ttl 30m)", ErrEmptyTTL)
	}

	ttl, err := time.ParseDuration(ttlStr)
	if err != nil {
		return 0, fmt.Errorf("%w: invalid TTL format: %v (use format like 1h, 24h, 30m, 1h30m)", ErrInvalidTTL, err)
	}
	if ttl < time.Second {
		return 0, fmt.Errorf("%w: TTL must be at least 1 second", ErrInvalidTTL)
	}
	if ttl > time.Duration(MaxTTLSeconds)*time.Second {
		return 0, fmt.Errorf("%w: TTL cannot exceed 365 days", ErrInvalidTTL)
	}

	return ttl, nil
}
