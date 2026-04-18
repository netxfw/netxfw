package rule

import (
	"fmt"

	"github.com/netxfw/netxfw/internal/utils/iputil"
)

// Selector identifies the network target for a rule.
type Selector struct {
	CIDR string
	Port uint16
}

// ParseSelector parses <ip>[:port] input into a normalized selector.
func ParseSelector(input string) (Selector, error) {
	host, port, err := iputil.ParseIPPort(input)
	if err == nil {
		return NewSelector(host, port)
	}

	if iputil.IsValidCIDR(input) {
		return NewSelector(input, 0)
	}

	return Selector{}, fmt.Errorf("%w: %s", ErrSelectorFormat, input)
}

// NewSelector validates and normalizes a selector.
func NewSelector(cidr string, port uint16) (Selector, error) {
	if err := ValidateIP(cidr); err != nil {
		return Selector{}, err
	}
	if err := ValidatePort(int(port), true); err != nil {
		return Selector{}, err
	}

	return Selector{
		CIDR: iputil.NormalizeCIDR(cidr),
		Port: port,
	}, nil
}

func (s Selector) Key() string {
	if s.Port == 0 {
		return s.CIDR
	}
	return fmt.Sprintf("%s:%d", s.CIDR, s.Port)
}
