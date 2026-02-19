// Package ppfilter provides Proxy Protocol parsing for NetXFW.
// Package ppfilter 为 NetXFW 提供 Proxy Protocol 解析。
// This package provides a simple user-space solution without requiring Nginx/HAProxy.
// 此包提供简单的用户态解决方案，无需 Nginx/HAProxy。
package ppfilter

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/livp123/netxfw/internal/proxyproto"
	"github.com/livp123/netxfw/internal/utils/logger"

	"go.uber.org/zap"
)

var (
	ErrNotEnabled        = errors.New("proxy protocol filter not enabled")
	ErrInvalidConnection = errors.New("invalid connection")
)

// Extractor extracts real IP from connections with Proxy Protocol.
// Extractor 从带有 Proxy Protocol 的连接中提取真实 IP。
type Extractor struct {
	parser     *proxyproto.Parser
	cache      *ConnectionCache
	trustedLBs []netip.Prefix
	enabled    bool
	mu         sync.RWMutex
	log        *zap.SugaredLogger
}

// Config represents the extractor configuration.
// Config 表示提取器配置。
type Config struct {
	// Enabled enables Proxy Protocol parsing.
	// Enabled 启用 Proxy Protocol 解析。
	Enabled bool

	// TrustedLBs are trusted load balancer IP ranges.
	// TrustedLBs 是可信的负载均衡器 IP 范围。
	TrustedLBs []string

	// CacheTTL is the cache entry TTL.
	// CacheTTL 是缓存条目 TTL。
	CacheTTL time.Duration
}

// NewExtractor creates a new Proxy Protocol extractor.
// NewExtractor 创建新的 Proxy Protocol 提取器。
func NewExtractor(cfg *Config) *Extractor {
	e := &Extractor{
		parser:     proxyproto.NewParser(cfg.Enabled),
		cache:      NewConnectionCache(cfg.CacheTTL),
		trustedLBs: make([]netip.Prefix, 0),
		enabled:    cfg.Enabled,
		log:        logger.Get(context.Background()),
	}

	// Parse trusted LB ranges.
	// 解析可信 LB 范围。
	for _, cidr := range cfg.TrustedLBs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			e.log.Warnf("Invalid trusted LB CIDR: %s: %v", cidr, err)
			continue
		}
		e.trustedLBs = append(e.trustedLBs, prefix)
	}

	return e
}

// WrapListener wraps a net.Listener to extract real IP from Proxy Protocol.
// WrapListener 包装 net.Listener 以从 Proxy Protocol 提取真实 IP。
func (e *Extractor) WrapListener(ln net.Listener) net.Listener {
	if !e.enabled {
		return ln
	}

	return &ProxyProtocolListener{
		Listener:   ln,
		extractor:  e,
		trustedLBs: e.trustedLBs,
	}
}

// WrapConn wraps a net.Conn to extract real IP from Proxy Protocol.
// WrapConn 包装 net.Conn 以从 Proxy Protocol 提取真实 IP。
func (e *Extractor) WrapConn(conn net.Conn) (net.Conn, netip.Addr, error) {
	if !e.enabled {
		return conn, netip.Addr{}, ErrNotEnabled
	}

	// Get remote address.
	// 获取远程地址。
	remoteAddr := conn.RemoteAddr()
	if remoteAddr == nil {
		return conn, netip.Addr{}, ErrInvalidConnection
	}

	// Parse LB IP.
	// 解析 LB IP。
	lbIP, err := netip.ParseAddrPort(remoteAddr.String())
	if err != nil {
		return conn, netip.Addr{}, err
	}

	// Check if connection is from trusted LB.
	// 检查连接是否来自可信 LB。
	if !e.isTrustedLB(lbIP.Addr()) {
		// Not from trusted LB, return original connection.
		// 不是来自可信 LB，返回原始连接。
		return conn, lbIP.Addr(), nil
	}

	// Read Proxy Protocol header.
	// 读取 Proxy Protocol 头。
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return conn, lbIP.Addr(), err
	}

	// Parse Proxy Protocol header.
	// 解析 Proxy Protocol 头。
	header, consumed, err := e.parser.Parse(buf[:n])
	if err != nil {
		e.log.Warnf("Failed to parse Proxy Protocol: %v", err)
		// Return remaining data as a buffered connection.
		// 将剩余数据作为缓冲连接返回。
		return &BufferedConn{Conn: conn, buf: buf[:n]}, lbIP.Addr(), nil
	}

	if header == nil {
		// No Proxy Protocol header.
		// 没有 Proxy Protocol 头。
		return &BufferedConn{Conn: conn, buf: buf[:n]}, lbIP.Addr(), nil
	}

	// Cache the real IP.
	// 缓存真实 IP。
	connID := generateConnID(lbIP.Addr(), header.SourceIP)
	e.cache.Set(connID, &ConnectionInfo{
		RealIP:    header.SourceIP,
		RealPort:  header.SourcePort,
		LBIP:      lbIP.Addr(),
		LBPort:    lbIP.Port(),
		Timestamp: time.Now(),
	})

	// Return buffered connection with remaining data.
	// 返回带有剩余数据的缓冲连接。
	return &BufferedConn{
		Conn: conn,
		buf:  buf[consumed:n],
	}, header.SourceIP, nil
}

// GetRealIP gets the real IP for a connection ID.
// GetRealIP 获取连接 ID 的真实 IP。
func (e *Extractor) GetRealIP(connID string) (netip.Addr, bool) {
	return e.cache.GetRealIP(connID)
}

// isTrustedLB checks if an IP is from a trusted load balancer.
// isTrustedLB 检查 IP 是否来自可信负载均衡器。
func (e *Extractor) isTrustedLB(ip netip.Addr) bool {
	for _, prefix := range e.trustedLBs {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

// IsEnabled returns whether the extractor is enabled.
// IsEnabled 返回提取器是否启用。
func (e *Extractor) IsEnabled() bool {
	return e.enabled
}

// ProxyProtocolListener wraps a net.Listener to handle Proxy Protocol.
// ProxyProtocolListener 包装 net.Listener 以处理 Proxy Protocol。
type ProxyProtocolListener struct {
	net.Listener
	extractor  *Extractor
	trustedLBs []netip.Prefix
}

// Accept accepts a connection and extracts real IP if Proxy Protocol is present.
// Accept 接受连接并在存在 Proxy Protocol 时提取真实 IP。
func (ln *ProxyProtocolListener) Accept() (net.Conn, error) {
	conn, err := ln.Listener.Accept()
	if err != nil {
		return nil, err
	}

	if !ln.extractor.enabled {
		return conn, nil
	}

	// Wrap connection to extract real IP.
	// 包装连接以提取真实 IP。
	wrappedConn, _, err := ln.extractor.WrapConn(conn)
	if err != nil {
		return conn, nil
	}

	return wrappedConn, nil
}

// BufferedConn wraps a net.Conn with buffered data.
// BufferedConn 包装带有缓冲数据的 net.Conn。
type BufferedConn struct {
	net.Conn
	buf []byte
	pos int
}

// Read reads data from the connection.
// Read 从连接读取数据。
func (c *BufferedConn) Read(b []byte) (int, error) {
	if c.pos < len(c.buf) {
		n := copy(b, c.buf[c.pos:])
		c.pos += n
		return n, nil
	}
	return c.Conn.Read(b)
}

// ConnectionInfo stores information about a connection.
// ConnectionInfo 存储连接信息。
type ConnectionInfo struct {
	RealIP    netip.Addr
	RealPort  uint16
	LBIP      netip.Addr
	LBPort    uint16
	Timestamp time.Time
}

// ConnectionCache caches connection information.
// ConnectionCache 缓存连接信息。
type ConnectionCache struct {
	entries map[string]*ConnectionInfo
	mu      sync.RWMutex
	ttl     time.Duration
}

// NewConnectionCache creates a new ConnectionCache.
// NewConnectionCache 创建新的 ConnectionCache。
func NewConnectionCache(ttl time.Duration) *ConnectionCache {
	if ttl == 0 {
		ttl = 5 * time.Minute
	}

	c := &ConnectionCache{
		entries: make(map[string]*ConnectionInfo),
		ttl:     ttl,
	}

	go c.cleanup()

	return c
}

// Set stores connection information.
// Set 存储连接信息。
func (c *ConnectionCache) Set(connID string, info *ConnectionInfo) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[connID] = info
}

// Get retrieves connection information.
// Get 获取连接信息。
func (c *ConnectionCache) Get(connID string) *ConnectionInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.entries[connID]
}

// GetRealIP retrieves the real IP for a connection ID.
// GetRealIP 获取连接 ID 的真实 IP。
func (c *ConnectionCache) GetRealIP(connID string) (netip.Addr, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	info, ok := c.entries[connID]
	if !ok {
		return netip.Addr{}, false
	}
	return info.RealIP, true
}

// Delete removes connection information.
// Delete 删除连接信息。
func (c *ConnectionCache) Delete(connID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, connID)
}

// cleanup periodically removes expired entries.
// cleanup 定期清理过期条目。
func (c *ConnectionCache) cleanup() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		c.mu.Lock()
		now := time.Now()
		for id, info := range c.entries {
			if now.Sub(info.Timestamp) > c.ttl {
				delete(c.entries, id)
			}
		}
		c.mu.Unlock()
	}
}

// generateConnID generates a unique connection ID.
// generateConnID 生成唯一的连接 ID。
func generateConnID(lbIP, realIP netip.Addr) string {
	return lbIP.String() + ":" + realIP.String()
}
