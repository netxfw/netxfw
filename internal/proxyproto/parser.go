// Package proxyproto provides Proxy Protocol parsing support for NetXFW.
// Package proxyproto 为 NetXFW 提供 Proxy Protocol 解析支持。
package proxyproto

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

// Protocol version and command constants.
// 协议版本和命令常量。
const (
	SignatureV1 = "PROXY"
	SignatureV2 = "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A"

	Version2 = 0x20
	Version1 = 0x10

	CommandLocal = 0x00
	CommandProxy = 0x01

	AFUnspec = 0x00
	AFInet   = 0x10
	AFInet6  = 0x20
	AFUnix   = 0x30

	StreamUnspec = 0x00
	StreamTCP    = 0x01
	StreamUDP    = 0x02
)

var (
	ErrInvalidSignature = errors.New("invalid proxy protocol signature")
	ErrInvalidHeader    = errors.New("invalid proxy protocol header")
	ErrUnsupported      = errors.New("unsupported proxy protocol version")
)

// Header represents a Proxy Protocol header.
// Header 表示 Proxy Protocol 头。
type Header struct {
	Version         byte
	Command         byte
	SourceIP        netip.Addr
	DestinationIP   netip.Addr
	SourcePort      uint16
	DestinationPort uint16
}

// Parser parses Proxy Protocol headers.
// Parser 解析 Proxy Protocol 头。
type Parser struct {
	enabled bool
}

// NewParser creates a new Proxy Protocol parser.
// NewParser 创建新的 Proxy Protocol 解析器。
func NewParser(enabled bool) *Parser {
	return &Parser{enabled: enabled}
}

// Parse parses a Proxy Protocol header from the given data.
// Parse 从给定数据解析 Proxy Protocol 头。
func (p *Parser) Parse(data []byte) (*Header, int, error) {
	if !p.enabled {
		return nil, 0, nil
	}

	if len(data) < 16 {
		return nil, 0, ErrInvalidHeader
	}

	// Check for V2 signature.
	// 检查 V2 签名。
	if string(data[:12]) == SignatureV2 {
		return p.parseV2(data)
	}

	// Check for V1 signature.
	// 检查 V1 签名。
	if len(data) >= 5 && string(data[:5]) == SignatureV1 {
		return p.parseV1(data)
	}

	return nil, 0, ErrInvalidSignature
}

// parseV2 parses Proxy Protocol v2 header.
// parseV2 解析 Proxy Protocol v2 头。
func (p *Parser) parseV2(data []byte) (*Header, int, error) {
	if len(data) < 16 {
		return nil, 0, ErrInvalidHeader
	}

	header := &Header{
		Version: 2,
	}

	// Parse version and command.
	// 解析版本和命令。
	verCmd := data[12]
	header.Version = (verCmd & 0xF0) >> 4
	header.Command = verCmd & 0x0F

	// Parse address family and protocol.
	// 解析地址族和协议。
	family := data[13]

	// Parse address length.
	// 解析地址长度。
	addrLen := binary.BigEndian.Uint16(data[14:16])

	if len(data) < int(16+addrLen) {
		return nil, 0, ErrInvalidHeader
	}

	offset := 16

	switch family {
	case AFInet | StreamTCP, AFInet | StreamUDP:
		// IPv4.
		// IPv4 地址。
		if addrLen != 12 {
			return nil, 0, ErrInvalidHeader
		}
		if err := parseIPv4Addresses(header, data, offset); err != nil {
			return nil, 0, err
		}
		return header, 16 + int(addrLen), nil

	case AFInet6 | StreamTCP, AFInet6 | StreamUDP:
		// IPv6.
		// IPv6 地址。
		if addrLen != 36 {
			return nil, 0, ErrInvalidHeader
		}
		if err := parseIPv6Addresses(header, data, offset); err != nil {
			return nil, 0, err
		}
		return header, 16 + int(addrLen), nil

	case AFUnspec, AFUnix:
		// Unsupported or unspecified.
		// 不支持或未指定。
		return header, 16 + int(addrLen), nil

	default:
		return nil, 0, ErrUnsupported
	}
}

// parseIPv4Addresses parses IPv4 addresses from the PROXY protocol v2 header.
// parseIPv4Addresses 从 PROXY 协议 v2 头部解析 IPv4 地址。
func parseIPv4Addresses(header *Header, data []byte, offset int) error {
	srcIP := netip.AddrFrom4([4]byte(data[offset : offset+4]))
	dstIP := netip.AddrFrom4([4]byte(data[offset+4 : offset+8]))
	srcPort := binary.BigEndian.Uint16(data[offset+8 : offset+10])
	dstPort := binary.BigEndian.Uint16(data[offset+10 : offset+12])

	header.SourceIP = srcIP
	header.DestinationIP = dstIP
	header.SourcePort = srcPort
	header.DestinationPort = dstPort
	return nil
}

// parseIPv6Addresses parses IPv6 addresses from the PROXY protocol v2 header.
// parseIPv6Addresses 从 PROXY 协议 v2 头部解析 IPv6 地址。
func parseIPv6Addresses(header *Header, data []byte, offset int) error {
	srcIP := netip.AddrFrom16([16]byte(data[offset : offset+16]))
	dstIP := netip.AddrFrom16([16]byte(data[offset+16 : offset+32]))
	srcPort := binary.BigEndian.Uint16(data[offset+32 : offset+34])
	dstPort := binary.BigEndian.Uint16(data[offset+34 : offset+36])

	header.SourceIP = srcIP
	header.DestinationIP = dstIP
	header.SourcePort = srcPort
	header.DestinationPort = dstPort
	return nil
}

// parseV1 parses Proxy Protocol v1 header.
// parseV1 解析 Proxy Protocol v1 头。
func (p *Parser) parseV1(data []byte) (*Header, int, error) {
	// Find CRLF.
	// 查找 CRLF。
	var end int
	for i := 0; i < len(data)-1; i++ {
		if data[i] == '\r' && data[i+1] == '\n' {
			end = i
			break
		}
	}

	if end == 0 {
		return nil, 0, ErrInvalidHeader
	}

	// Parse header string.
	// 解析头字符串。
	headerStr := string(data[:end])
	parts := splitHeader(headerStr)

	if len(parts) < 6 {
		return nil, 0, ErrInvalidHeader
	}

	header := &Header{
		Version: 1,
	}

	// PROXY TCP4 192.168.0.1 192.168.0.11 56324 443
	// PROXY TCP6 2001:db8::1 2001:db8::2 56324 443
	if parts[1] == "TCP4" || parts[1] == "TCP6" {
		srcIP, err := netip.ParseAddr(parts[2])
		if err != nil {
			return nil, 0, err
		}
		dstIP, err := netip.ParseAddr(parts[3])
		if err != nil {
			return nil, 0, err
		}

		srcPort := parsePort(parts[4])
		dstPort := parsePort(parts[5])

		header.SourceIP = srcIP
		header.DestinationIP = dstIP
		header.SourcePort = srcPort
		header.DestinationPort = dstPort
	}

	return header, end + 2, nil
}

// splitHeader splits the header string by spaces.
// splitHeader 按空格分割头字符串。
func splitHeader(s string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	parts = append(parts, s[start:])
	return parts
}

// parsePort parses a port number from string.
// parsePort 从字符串解析端口号。
func parsePort(s string) uint16 {
	var port uint16
	for _, c := range s {
		if c >= '0' && c <= '9' {
			port = port*10 + uint16(c-'0')
		}
	}
	return port
}

// IsEnabled returns whether the parser is enabled.
// IsEnabled 返回解析器是否启用。
func (p *Parser) IsEnabled() bool {
	return p.enabled
}

// RealIPCache caches real IP addresses extracted from Proxy Protocol.
// RealIPCache 缓存从 Proxy Protocol 提取的真实 IP 地址。
type RealIPCache struct {
	entries map[string]*Header
}

// NewRealIPCache creates a new RealIPCache.
// NewRealIPCache 创建新的 RealIPCache。
func NewRealIPCache() *RealIPCache {
	return &RealIPCache{
		entries: make(map[string]*Header),
	}
}

// Set stores a header entry.
// Set 存储头条目。
func (c *RealIPCache) Set(key string, header *Header) {
	c.entries[key] = header
}

// Get retrieves a header entry.
// Get 获取头条目。
func (c *RealIPCache) Get(key string) *Header {
	return c.entries[key]
}

// Delete removes a header entry.
// Delete 删除头条目。
func (c *RealIPCache) Delete(key string) {
	delete(c.entries, key)
}
