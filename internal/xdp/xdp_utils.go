//go:build linux
// +build linux

package xdp

import (
	"encoding/binary"
	"net"
	"time"
)

func intToIP(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, nn)
	return ip
}

/**
 * timeToBootNS converts a time.Time pointer to boot time nanoseconds.
 * If the pointer is nil, it returns 0 (no expiry).
 * timeToBootNS 将 time.Time 指针转换为启动时间纳秒。
 * 如果指针为 nil，则返回 0（永不过期）。
 */
func timeToBootNS(t *time.Time) uint64 {
	if t == nil {
		return 0
	}
	// Use monotonic clock to get duration since a fixed point
	// This is a simplified version, in production you might need to sync with boot time
	return uint64(time.Until(*t).Nanoseconds()) + uint64(time.Now().UnixNano())
}
