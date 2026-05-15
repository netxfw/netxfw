//go:build integration

package performance

import (
	"net"
	"testing"
)

func BenchmarkIPParsing(b *testing.B) {
	ips := []string{
		"192.168.1.1",
		"10.0.0.1",
		"172.16.0.1",
		"2001:db8::1",
		"::1",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ip := ips[i%len(ips)]
		_ = net.ParseIP(ip)
	}

	if b.N > 0 {
		nsPerOp := float64(b.Elapsed().Nanoseconds()) / float64(b.N)
		SaveBenchmarkResult("IPParsing", nsPerOp, 0, 0)
	}
}

func BenchmarkCIDRParsing(b *testing.B) {
	cidrs := []string{
		"192.168.1.0/24",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"2001:db8::/32",
		"::/0",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cidr := cidrs[i%len(cidrs)]
		_, _, _ = net.ParseCIDR(cidr)
	}

	if b.N > 0 {
		nsPerOp := float64(b.Elapsed().Nanoseconds()) / float64(b.N)
		SaveBenchmarkResult("CIDRParsing", nsPerOp, 0, 0)
	}
}

func BenchmarkIPValidation(b *testing.B) {
	ips := []string{
		"192.168.1.1",
		"invalid",
		"10.0.0.1",
		"also-invalid",
		"172.16.0.1",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ip := ips[i%len(ips)]
		_ = net.ParseIP(ip) != nil
	}

	if b.N > 0 {
		nsPerOp := float64(b.Elapsed().Nanoseconds()) / float64(b.N)
		SaveBenchmarkResult("IPValidation", nsPerOp, 0, 0)
	}
}

func BenchmarkMapLookup(b *testing.B) {
	lookupMap := make(map[string]bool)
	for i := 0; i < 10000; i++ {
		lookupMap[net.IP{192, 168, byte(i >> 8), byte(i)}.String()] = true
	}

	testIPs := make([]string, 1000)
	for i := 0; i < 1000; i++ {
		testIPs[i] = net.IP{192, 168, byte(i >> 8), byte(i)}.String()
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = lookupMap[testIPs[i%len(testIPs)]]
	}

	if b.N > 0 {
		nsPerOp := float64(b.Elapsed().Nanoseconds()) / float64(b.N)
		SaveBenchmarkResult("MapLookup", nsPerOp, 0, 0)
	}
}

func BenchmarkMapInsert(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m := make(map[string]bool)
		for j := 0; j < 1000; j++ {
			m[net.IP{192, 168, byte(j >> 8), byte(j)}.String()] = true
		}
	}

	if b.N > 0 {
		nsPerOp := float64(b.Elapsed().Nanoseconds()) / float64(b.N)
		SaveBenchmarkResult("MapInsert", nsPerOp, 0, 0)
	}
}

func BenchmarkSliceAppend(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var slice []string
		for j := 0; j < 1000; j++ {
			slice = append(slice, net.IP{192, 168, byte(j >> 8), byte(j)}.String())
		}
	}

	if b.N > 0 {
		nsPerOp := float64(b.Elapsed().Nanoseconds()) / float64(b.N)
		SaveBenchmarkResult("SliceAppend", nsPerOp, 0, 0)
	}
}
