package logengine

import (
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestNewCounter tests NewCounter function
// TestNewCounter 测试 NewCounter 函数
func TestNewCounter(t *testing.T) {
	t.Run("Default window", func(t *testing.T) {
		c := NewCounter(0)
		assert.Equal(t, 3600, c.MaxWindowSeconds())
	})

	t.Run("Custom window", func(t *testing.T) {
		c := NewCounter(7200)
		assert.Equal(t, 7200, c.MaxWindowSeconds())
	})

	t.Run("Negative window", func(t *testing.T) {
		c := NewCounter(-1)
		assert.Equal(t, 3600, c.MaxWindowSeconds())
	})
}

// TestCounter_Inc tests Counter Inc method
// TestCounter_Inc 测试 Counter Inc 方法
func TestCounter_Inc(t *testing.T) {
	c := NewCounter(60)
	ip, _ := netip.ParseAddr("192.168.1.1")

	// Increment counter
	c.Inc(ip)

	// Verify count
	count := c.Count(ip, 60)
	assert.Equal(t, 1, count)
}

// TestCounter_Count tests Counter Count method
// TestCounter_Count 测试 Counter Count 方法
func TestCounter_Count(t *testing.T) {
	c := NewCounter(60)
	ip, _ := netip.ParseAddr("192.168.1.1")

	t.Run("No entries", func(t *testing.T) {
		count := c.Count(ip, 60)
		assert.Equal(t, 0, count)
	})

	t.Run("Single entry", func(t *testing.T) {
		c.Inc(ip)
		count := c.Count(ip, 60)
		assert.Equal(t, 1, count)
	})

	t.Run("Multiple entries", func(t *testing.T) {
		for i := 0; i < 5; i++ {
			c.Inc(ip)
		}
		count := c.Count(ip, 60)
		assert.Equal(t, 6, count)
	})

	t.Run("Different IP", func(t *testing.T) {
		ip2, _ := netip.ParseAddr("10.0.0.1")
		count := c.Count(ip2, 60)
		assert.Equal(t, 0, count)
	})
}

// TestCounter_MultipleIPs tests counter with multiple IPs
// TestCounter_MultipleIPs 测试多个 IP 的计数器
func TestCounter_MultipleIPs(t *testing.T) {
	c := NewCounter(60)

	ips := []string{
		"192.168.1.1",
		"192.168.1.2",
		"10.0.0.1",
		"172.16.0.1",
	}

	for i, ipStr := range ips {
		ip, _ := netip.ParseAddr(ipStr)
		for j := 0; j <= i; j++ {
			c.Inc(ip)
		}
	}

	for i, ipStr := range ips {
		ip, _ := netip.ParseAddr(ipStr)
		count := c.Count(ip, 60)
		assert.Equal(t, i+1, count)
	}
}

// TestCounter_IPv6 tests counter with IPv6 addresses
// TestCounter_IPv6 测试 IPv6 地址的计数器
func TestCounter_IPv6(t *testing.T) {
	c := NewCounter(60)

	ip1, _ := netip.ParseAddr("2001:db8::1")
	ip2, _ := netip.ParseAddr("2001:db8::2")

	c.Inc(ip1)
	c.Inc(ip1)
	c.Inc(ip2)

	assert.Equal(t, 2, c.Count(ip1, 60))
	assert.Equal(t, 1, c.Count(ip2, 60))
}

// TestCounter_WindowSize tests different window sizes
// TestCounter_WindowSize 测试不同的窗口大小
func TestCounter_WindowSize(t *testing.T) {
	c := NewCounter(60)
	ip, _ := netip.ParseAddr("192.168.1.1")

	c.Inc(ip)

	// Window larger than max
	count := c.Count(ip, 100)
	assert.Equal(t, 1, count)

	// Window smaller than max
	count = c.Count(ip, 10)
	assert.Equal(t, 1, count)
}

// TestCounter_Cleanup tests Cleanup method
// TestCounter_Cleanup 测试 Cleanup 方法
func TestCounter_Cleanup(t *testing.T) {
	c := NewCounter(1) // 1 second window
	ip, _ := netip.ParseAddr("192.168.1.1")

	c.Inc(ip)

	// Wait for window to expire
	time.Sleep(2 * time.Second)

	c.Cleanup()

	// Entry should be cleaned up
	count := c.Count(ip, 1)
	assert.Equal(t, 0, count)
}

// TestCounter_MaxWindowSeconds tests MaxWindowSeconds method
// TestCounter_MaxWindowSeconds 测试 MaxWindowSeconds 方法
func TestCounter_MaxWindowSeconds(t *testing.T) {
	c := NewCounter(3600)
	assert.Equal(t, 3600, c.MaxWindowSeconds())
}

// TestCounter_GetShard tests shard distribution
// TestCounter_GetShard 测试分片分布
func TestCounter_GetShard(t *testing.T) {
	c := NewCounter(60)

	ip1, _ := netip.ParseAddr("192.168.1.1")
	ip2, _ := netip.ParseAddr("192.168.1.2")

	shard1 := c.getShard(ip1)
	shard2 := c.getShard(ip2)

	// Both shards should be valid
	assert.NotNil(t, shard1)
	assert.NotNil(t, shard2)
}

// TestCounter_ConcurrentAccess tests concurrent access
// TestCounter_ConcurrentAccess 测试并发访问
func TestCounter_ConcurrentAccess(t *testing.T) {
	c := NewCounter(60)
	ip, _ := netip.ParseAddr("192.168.1.1")

	done := make(chan bool)

	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				c.Inc(ip)
			}
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}

	count := c.Count(ip, 60)
	assert.Equal(t, 1000, count)
}
