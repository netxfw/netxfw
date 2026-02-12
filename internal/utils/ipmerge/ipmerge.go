package ipmerge

import (
	"encoding/binary"
	"net/netip"
	"sort"
)

// MergeCIDRsWithThreshold works like MergeCIDRs but also promotes smaller CIDRs to a larger subnet
// (IPv4 /v4Mask, IPv6 /v6Mask) if the number of rules within that subnet meets or exceeds the threshold.
func MergeCIDRsWithThreshold(cidrs []string, threshold int, v4Mask int, v6Mask int) ([]string, error) {
	// 1. First run standard merge to remove redundancies and combine adjacent ranges
	merged, err := MergeCIDRs(cidrs)
	if err != nil {
		return nil, err
	}

	if threshold <= 1 {
		return merged, nil
	}

	// Validate masks
	if v4Mask < 0 {
		v4Mask = 0
	} else if v4Mask > 32 {
		v4Mask = 32
	}
	if v6Mask < 0 {
		v6Mask = 0
	} else if v6Mask > 128 {
		v6Mask = 128
	}

	// 2. Group by parent subnet
	// Map key: Parent subnet string
	// Map value: List of child CIDRs that fall into this subnet
	groups := make(map[string][]string)
	var finalCidrs []string

	for _, c := range merged {
		prefix, err := netip.ParsePrefix(c)
		if err != nil {
			continue
		}

		isV4 := prefix.Addr().Is4()
		parentBits := v4Mask
		if !isV4 {
			parentBits = v6Mask
		}

		// If the prefix is already large enough (shorter length), keep it
		if prefix.Bits() <= parentBits {
			finalCidrs = append(finalCidrs, c)
			continue
		}

		// Calculate parent prefix
		addr := prefix.Addr()
		parent, _ := addr.Prefix(parentBits)
		parentStr := parent.String()

		groups[parentStr] = append(groups[parentStr], c)
	}

	// 3. Process groups
	for parent, children := range groups {
		if len(children) >= threshold {
			// Promote to parent
			finalCidrs = append(finalCidrs, parent)
		} else {
			// Keep children
			finalCidrs = append(finalCidrs, children...)
		}
	}

	// 4. Run standard merge again to cleanup any newly created adjacencies
	return MergeCIDRs(finalCidrs)
}

// MergeCIDRs takes a list of CIDR strings (IPv4 and IPv6) and returns a minimized list of CIDRs.
// It automatically filters out invalid CIDRs/IPs.
func MergeCIDRs(cidrs []string) ([]string, error) {
	var v4Ranges []ipRange
	var v6Ranges []ipRange

	for _, c := range cidrs {
		if c == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(c)
		if err != nil {
			// Try parsing as single IP
			addr, err := netip.ParseAddr(c)
			if err != nil {
				// Invalid, skip
				continue
			}
			prefix = netip.PrefixFrom(addr, addr.BitLen())
		} else {
			// Ensure the prefix is canonical (masked)
			prefix = prefix.Masked()
		}

		start := prefix.Addr()
		end := prefixLastIP(prefix)

		if start.Is4() {
			v4Ranges = append(v4Ranges, ipRange{start: start, end: end})
		} else {
			v6Ranges = append(v6Ranges, ipRange{start: start, end: end})
		}
	}

	mergedV4 := mergeRanges(v4Ranges)
	mergedV6 := mergeRanges(v6Ranges)

	var result []string
	for _, r := range mergedV4 {
		result = append(result, rangeToCIDRs(r.start, r.end)...)
	}
	for _, r := range mergedV6 {
		result = append(result, rangeToCIDRs(r.start, r.end)...)
	}
	return result, nil
}

type ipRange struct {
	start netip.Addr
	end   netip.Addr
}

func prefixLastIP(p netip.Prefix) netip.Addr {
	// In Go 1.18+, we don't have a direct LastIP method on Prefix.
	// But p.Masked() gives us the network address.
	// We can compute the last address by adding (1<<(bitlen-bits)) - 1.
	// Or more simply:
	// p.Range() returns (first, last) in newer Go versions, but let's implement a safe way.

	// Try to use p.Range() if available (it was added in Go 1.22, but we might be on older).
	// Since we can't rely on Go version here without checking, let's implement manually using 16 bytes.

	start := p.Addr()
	bits := p.Bits()
	length := start.BitLen()

	// If it's a single IP (/32 or /128), start == end
	if bits == length {
		return start
	}

	// Calculate the last IP
	// We need to flip the host bits to 1
	if start.Is4() {
		// IPv4 is mapped to ::ffff:1.2.3.4 in As16 if it was created that way,
		// but netip.Addr handles 4-byte and 16-byte internal rep.
		// start.As4() gives [4]byte.
		ip4 := start.As4()
		// number of host bits = 32 - bits
		hostBits := 32 - bits

		// Fill host bits with 1s
		for i := 0; i < 4; i++ {
			// Determine if this byte is part of the host part
			// Byte index 0 is MSB.
			// e.g. /24. hostBits=8.
			// i=3 (last byte) is fully host.

			// A byte is fully host if (3-i)*8 < hostBits
			// A byte is partially host if ...

			// Simpler approach: convert to uint32, add size-1, convert back.
			// But that's annoying.
			// Let's stick to byte manipulation.
			if hostBits > (3-i)*8 {
				shift := 0
				if hostBits < (3-i+1)*8 {
					shift = (3-i+1)*8 - hostBits
				}
				// set bits from LSB up to 8-shift
				// e.g. shift=0 -> set all 8 bits
				// shift=2 -> set 6 bits (00111111) -> 0x3F
				mask := byte(0xFF >> shift)
				ip4[i] |= mask
			}
		}
		return netip.AddrFrom4(ip4)
	} else {
		// IPv6
		ip6 := start.As16()
		hostBits := 128 - bits
		for i := 0; i < 16; i++ {
			if hostBits > (15-i)*8 {
				shift := 0
				if hostBits < (15-i+1)*8 {
					shift = (15-i+1)*8 - hostBits
				}
				mask := byte(0xFF >> shift)
				ip6[i] |= mask
			}
		}
		return netip.AddrFrom16(ip6)
	}
}

func mergeRanges(ranges []ipRange) []ipRange {
	if len(ranges) == 0 {
		return nil
	}

	// Sort by start address
	sort.Slice(ranges, func(i, j int) bool {
		return ranges[i].start.Less(ranges[j].start)
	})

	var merged []ipRange
	current := ranges[0]

	for i := 1; i < len(ranges); i++ {
		next := ranges[i]

		// Check if current overlaps or is adjacent to next
		// current.end + 1 >= next.start

		// Calculate current.end + 1
		currentEndNext := nextIP(current.end)

		// If current.end is Max (255.255.255.255), nextIP wraps or we handle it.
		// Since we sorted, next.start >= current.start.
		// Overlap: next.start <= current.end
		// Adjacent: next.start == current.end + 1

		isOverlap := !next.start.IsValid() || next.start.Compare(current.end) <= 0
		isAdjacent := currentEndNext.IsValid() && next.start == currentEndNext

		if isOverlap || isAdjacent {
			// Merge
			if current.end.Less(next.end) {
				current.end = next.end
			}
		} else {
			merged = append(merged, current)
			current = next
		}
	}
	merged = append(merged, current)
	return merged
}

func nextIP(ip netip.Addr) netip.Addr {
	return ip.Next()
}

func rangeToCIDRs(start, end netip.Addr) []string {
	var cidrs []string

	for start.Compare(end) <= 0 {
		// Find max prefix length such that prefix starts at 'start' and prefix.End <= end
		// We start with the largest possible block (smallest prefix length) and narrow down?
		// No, we start with the current 'start' and try to find the largest block that fits.

		// 1. Determine the number of trailing zeros in 'start' to see alignment.
		// 2. Determine the size available (end - start + 1).

		// Max bits (32 or 128)
		bitLen := start.BitLen()

		// Find the largest CIDR starting at 'start' that is <= 'end'
		// Iterate bits from 0 (whole space) to bitLen (single IP).
		// But we need the *largest* block, so smallest prefix length.

		// Heuristic:
		// Try prefix length L such that:
		// 1. start is aligned to L (start & hostmask == 0)
		// 2. start + size(L) - 1 <= end

		// Start checking from L such that block size is largest possible.
		// Max block size is constrained by:
		// a) Alignment of start (trailing zeros)
		// b) Difference between start and end

		current := start

		// Maximize block size

		// Find max step (host bits) allowed by alignment
		// Count trailing zeros
		zeros := countTrailingZeros(current)

		// Find max step allowed by size
		// We can't easily do math on IP addrs, so we iterate down.
		// Or we can try to find the biggest prefix that fits.

		found := false
		for hostBits := zeros; hostBits >= 0; hostBits-- {
			// Construct prefix
			prefixLen := bitLen - hostBits
			p := netip.PrefixFrom(current, prefixLen)

			// Check if this prefix is valid (it should be because we checked alignment via zeros)
			// Check if p.End() <= end
			last := prefixLastIP(p)

			if last.Compare(end) <= 0 {
				cidrs = append(cidrs, p.String())

				// Move start to next
				if last.Compare(end) == 0 {
					// Done
					return cidrs
				}
				start = last.Next()
				if !start.IsValid() {
					// Overflow, should not happen if logic is correct unless end is Max
					return cidrs
				}
				found = true
				break
			}
		}

		if !found {
			// Should not happen as /32 or /128 (hostBits=0) always fits if start <= end
			// Fallback
			cidrs = append(cidrs, netip.PrefixFrom(current, bitLen).String())
			start = current.Next()
		}
	}

	return cidrs
}

func countTrailingZeros(ip netip.Addr) int {
	if ip.Is4() {
		b := ip.As4()
		v := binary.BigEndian.Uint32(b[:])
		return countTrailingZeros32(v)
	}
	b := ip.As16()
	// Count 128-bit trailing zeros
	// Check lower 64 bits (bytes 8-15)
	low := binary.BigEndian.Uint64(b[8:])
	if low != 0 {
		return countTrailingZeros64(low)
	}
	high := binary.BigEndian.Uint64(b[:8])
	return 64 + countTrailingZeros64(high)
}

func countTrailingZeros32(x uint32) int {
	if x == 0 {
		return 32
	}
	n := 0
	if (x & 0x0000FFFF) == 0 {
		n += 16
		x >>= 16
	}
	if (x & 0x000000FF) == 0 {
		n += 8
		x >>= 8
	}
	if (x & 0x0000000F) == 0 {
		n += 4
		x >>= 4
	}
	if (x & 0x00000003) == 0 {
		n += 2
		x >>= 2
	}
	if (x & 0x00000001) == 0 {
		n += 1
	}
	return n
}

func countTrailingZeros64(x uint64) int {
	if x == 0 {
		return 64
	}
	n := 0
	if (x & 0xFFFFFFFF) == 0 {
		n += 32
		x >>= 32
	}
	if (x & 0xFFFF) == 0 {
		n += 16
		x >>= 16
	}
	if (x & 0xFF) == 0 {
		n += 8
		x >>= 8
	}
	if (x & 0xF) == 0 {
		n += 4
		x >>= 4
	}
	if (x & 0x3) == 0 {
		n += 2
		x >>= 2
	}
	if (x & 0x1) == 0 {
		n += 1
	}
	return n
}
