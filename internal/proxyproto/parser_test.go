// Package proxyproto provides Proxy Protocol parsing support for NetXFW.
// Package proxyproto 为 NetXFW 提供 Proxy Protocol 解析支持。
package proxyproto

import (
	"net/netip"
	"testing"
)

// TestParseV2IPv4 tests Proxy Protocol v2 IPv4 parsing.
// TestParseV2IPv4 测试 Proxy Protocol v2 IPv4 解析。
func TestParseV2IPv4(t *testing.T) {
	parser := NewParser(true)

	// Construct a valid v2 header for IPv4.
	// 构造有效的 v2 IPv4 头。
	header := []byte{
		// Signature.
		0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
		// Version (2) + Command (PROXY).
		0x21,
		// Family (IPv4) + Protocol (TCP).
		0x11,
		// Address length (12 bytes for IPv4).
		0x00, 0x0C,
		// Source IP: 192.168.1.100.
		0xC0, 0xA8, 0x01, 0x64,
		// Destination IP: 10.0.0.1.
		0x0A, 0x00, 0x00, 0x01,
		// Source port: 56324.
		0xDC, 0x04,
		// Destination port: 443.
		0x01, 0xBB,
	}

	result, consumed, err := parser.Parse(header)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if consumed != 28 {
		t.Errorf("Expected consumed 28, got %d", consumed)
	}

	if result.SourceIP.String() != "192.168.1.100" {
		t.Errorf("Expected source IP 192.168.1.100, got %s", result.SourceIP)
	}

	if result.DestinationIP.String() != "10.0.0.1" {
		t.Errorf("Expected destination IP 10.0.0.1, got %s", result.DestinationIP)
	}

	if result.SourcePort != 56324 {
		t.Errorf("Expected source port 56324, got %d", result.SourcePort)
	}

	if result.DestinationPort != 443 {
		t.Errorf("Expected destination port 443, got %d", result.DestinationPort)
	}
}

// TestParseV1IPv4 tests Proxy Protocol v1 IPv4 parsing.
// TestParseV1IPv4 测试 Proxy Protocol v1 IPv4 解析。
func TestParseV1IPv4(t *testing.T) {
	parser := NewParser(true)

	// v1 header string.
	// v1 头字符串。
	header := []byte("PROXY TCP4 192.168.1.100 10.0.0.1 56324 443\r\n")

	result, consumed, err := parser.Parse(header)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if result.SourceIP.String() != "192.168.1.100" {
		t.Errorf("Expected source IP 192.168.1.100, got %s", result.SourceIP)
	}

	if result.DestinationIP.String() != "10.0.0.1" {
		t.Errorf("Expected destination IP 10.0.0.1, got %s", result.DestinationIP)
	}

	if result.SourcePort != 56324 {
		t.Errorf("Expected source port 56324, got %d", result.SourcePort)
	}

	if result.DestinationPort != 443 {
		t.Errorf("Expected destination port 443, got %d", result.DestinationPort)
	}

	if consumed != len(header) {
		t.Errorf("Expected consumed %d, got %d", len(header), consumed)
	}
}

// TestParseDisabled tests parser when disabled.
// TestParseDisabled 测试禁用时的解析器。
func TestParseDisabled(t *testing.T) {
	parser := NewParser(false)

	header := []byte("PROXY TCP4 192.168.1.100 10.0.0.1 56324 443\r\n")

	result, consumed, err := parser.Parse(header)
	if err != nil {
		t.Fatalf("Parse should not fail when disabled: %v", err)
	}

	if result != nil {
		t.Error("Expected nil result when disabled")
	}

	if consumed != 0 {
		t.Errorf("Expected consumed 0 when disabled, got %d", consumed)
	}
}

// TestRealIPCache tests the RealIPCache.
// TestRealIPCache 测试 RealIPCache。
func TestRealIPCache(t *testing.T) {
	cache := NewRealIPCache()

	header := &Header{
		SourceIP:        mustParseAddr("192.168.1.100"),
		DestinationIP:   mustParseAddr("10.0.0.1"),
		SourcePort:      56324,
		DestinationPort: 443,
	}

	cache.Set("test-key", header)

	result := cache.Get("test-key")
	if result == nil {
		t.Fatal("Expected to find entry in cache")
	}

	if result.SourceIP.String() != "192.168.1.100" {
		t.Errorf("Expected source IP 192.168.1.100, got %s", result.SourceIP)
	}

	cache.Delete("test-key")

	result = cache.Get("test-key")
	if result != nil {
		t.Error("Expected entry to be deleted")
	}
}

// mustParseAddr parses an IP address or panics.
// mustParseAddr 解析 IP 地址或 panic。
func mustParseAddr(s string) netip.Addr {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		panic(err)
	}
	return addr
}
