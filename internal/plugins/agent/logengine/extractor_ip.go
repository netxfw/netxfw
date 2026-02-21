package logengine

import (
	"net/netip"
)

// IPExtractor extracts IP addresses from text without regex.
type IPExtractor struct{}

// NewIPExtractor creates a new IPExtractor.
func NewIPExtractor() *IPExtractor {
	return &IPExtractor{}
}

// ExtractIPs finds all valid unique IPs in a string.
func (e *IPExtractor) ExtractIPs(line string) []netip.Addr {
	return e.ExtractIPsWithBuf(line, nil)
}

// ExtractIPsWithBuf finds IPs using a provided buffer to minimize allocation.
func (e *IPExtractor) ExtractIPsWithBuf(line string, buf []netip.Addr) []netip.Addr {
	ips := buf[:0]

	// Scan for potential IP characters
	start := -1
	for i := 0; i < len(line); i++ {
		b := line[i]
		if isIPChar(b) {
			if start == -1 {
				start = i
			}
		} else {
			if start != -1 {
				// End of a potential IP segment
				candidate := line[start:i]
				// Basic optimization: Min length for valid IP (e.g. "1.1.1.1" or "::1")
				if len(candidate) >= 3 {
					if addr, err := netip.ParseAddr(candidate); err == nil {
						ips = append(ips, addr)
					}
				}
				start = -1
			}
		}
	}
	// Check last segment
	if start != -1 {
		candidate := line[start:]
		if len(candidate) >= 3 {
			if addr, err := netip.ParseAddr(candidate); err == nil {
				ips = append(ips, addr)
			}
		}
	}

	return uniqueIPs(ips)
}

func isIPChar(b byte) bool {
	return (b >= '0' && b <= '9') ||
		(b >= 'a' && b <= 'f') ||
		(b >= 'A' && b <= 'F') ||
		b == '.' || b == ':'
}

func uniqueIPs(ips []netip.Addr) []netip.Addr {
	if len(ips) <= 1 {
		return ips
	}
	// In-place deduplication (O(N^2) is fast for small N)
	uniqCount := 0
	for i := 0; i < len(ips); i++ {
		duplicate := false
		for j := 0; j < uniqCount; j++ {
			if ips[i] == ips[j] {
				duplicate = true
				break
			}
		}
		if !duplicate {
			ips[uniqCount] = ips[i]
			uniqCount++
		}
	}
	return ips[:uniqCount]
}
