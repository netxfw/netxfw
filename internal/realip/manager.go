// Package realip provides real IP extraction and blacklisting for cloud LB environments.
// Package realip 为云 LB 环境提供真实 IP 提取和黑名单功能。
package realip

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/netxfw/netxfw/internal/proxyproto"
	"github.com/netxfw/netxfw/internal/utils/logger"

	"go.uber.org/zap"
)

// BlacklistSyncFunc is a callback function to sync blacklist to XDP dynamic_blacklist map.
// BlacklistSyncFunc 是将黑名单同步到 XDP dynamic_blacklist Map 的回调函数。
// This callback is typically implemented using SDK's AddDynamicBlacklistIP method.
// 此回调通常使用 SDK 的 AddDynamicBlacklistIP 方法实现。
// Parameters:
// 参数:
//   - ip: the IP address to block (CIDR format supported)
//   - ip: 要封禁的 IP 地址（支持 CIDR 格式）
//   - ttl: time-to-live for the entry (0 means permanent)
//   - ttl: 条目的生存时间（0 表示永久）
type BlacklistSyncFunc func(ip string, ttl time.Duration) error

// Manager manages real IP extraction and blacklisting.
// Manager 管理真实 IP 提取和黑名单。
type Manager struct {
	parser     *proxyproto.Parser
	cache      *proxyproto.RealIPCache
	blacklist  map[string]*BlacklistEntry
	whitelist  map[string]bool
	trustedLBs []netip.Prefix
	mu         sync.RWMutex
	log        *zap.SugaredLogger

	// syncToXDPMap is the callback to sync blacklist to XDP dynamic_blacklist map.
	// syncToXDPMap 是将黑名单同步到 XDP dynamic_blacklist Map 的回调。
	syncToXDPMap BlacklistSyncFunc
}

// BlacklistEntry represents a blacklist entry with metadata.
// BlacklistEntry 表示带有元数据的黑名单条目。
type BlacklistEntry struct {
	IP        netip.Addr
	Reason    string
	Source    string // Source of the entry: "config", "api", "auto"
	ExpiresAt time.Time
	CreatedAt time.Time
}

// Config represents the real IP manager configuration.
// Config 表示真实 IP 管理器配置。
type Config struct {
	// ProxyProtocolEnabled enables Proxy Protocol parsing.
	// ProxyProtocolEnabled 启用 Proxy Protocol 解析。
	ProxyProtocolEnabled bool

	// TrustedLBs are trusted load balancer IP ranges.
	// TrustedLBs 是可信的负载均衡器 IP 范围。
	TrustedLBs []string

	// CacheExpiry is the cache entry expiry time.
	// CacheExpiry 是缓存条目过期时间。
	CacheExpiry time.Duration

	// SyncToXDPCallback is the callback to sync blacklist to XDP map.
	// SyncToXDPCallback 是将黑名单同步到 XDP Map 的回调。
	SyncToXDPCallback BlacklistSyncFunc
}

// NewManager creates a new real IP manager.
// NewManager 创建新的真实 IP 管理器。
func NewManager(cfg *Config) *Manager {
	m := &Manager{
		parser:       proxyproto.NewParser(cfg.ProxyProtocolEnabled),
		cache:        proxyproto.NewRealIPCache(),
		blacklist:    make(map[string]*BlacklistEntry),
		whitelist:    make(map[string]bool),
		trustedLBs:   make([]netip.Prefix, 0),
		log:          logger.Get(context.Background()),
		syncToXDPMap: cfg.SyncToXDPCallback,
	}

	// Parse trusted LB ranges.
	// 解析可信 LB 范围。
	for _, cidr := range cfg.TrustedLBs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			m.log.Warnf("Invalid trusted LB CIDR: %s: %v", cidr, err)
			continue
		}
		m.trustedLBs = append(m.trustedLBs, prefix)
	}

	return m
}

// ExtractRealIP extracts the real client IP from Proxy Protocol data.
// ExtractRealIP 从 Proxy Protocol 数据中提取真实客户端 IP。
func (m *Manager) ExtractRealIP(data []byte, lbIP string) (netip.Addr, error) {
	if !m.parser.IsEnabled() {
		// Proxy Protocol not enabled, return LB IP as source.
		// Proxy Protocol 未启用，返回 LB IP 作为源。
		addr, err := netip.ParseAddr(lbIP)
		if err != nil {
			return netip.Addr{}, err
		}
		return addr, nil
	}

	header, _, err := m.parser.Parse(data)
	if err != nil {
		m.log.Warnf("Failed to parse Proxy Protocol: %v", err)
		// Fallback to LB IP.
		// 回退到 LB IP。
		addr, err := netip.ParseAddr(lbIP)
		if err != nil {
			return netip.Addr{}, err
		}
		return addr, nil
	}

	if header == nil {
		// No Proxy Protocol header, use LB IP.
		// 没有 Proxy Protocol 头，使用 LB IP。
		addr, err := netip.ParseAddr(lbIP)
		if err != nil {
			return netip.Addr{}, err
		}
		return addr, nil
	}

	// Cache the mapping.
	// 缓存映射。
	m.cache.Set(lbIP, header)

	return header.SourceIP, nil
}

// IsTrustedLB checks if an IP is from a trusted load balancer.
// IsTrustedLB 检查 IP 是否来自可信负载均衡器。
func (m *Manager) IsTrustedLB(ip string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}

	for _, prefix := range m.trustedLBs {
		if prefix.Contains(addr) {
			return true
		}
	}

	return false
}

// AddToBlacklist adds an IP to the blacklist and syncs to XDP map.
// AddToBlacklist 将 IP 添加到黑名单并同步到 XDP Map。
// The IP will be written to dynamic_blacklist map for XDP-level filtering.
// IP 将被写入 dynamic_blacklist Map 以进行 XDP 级别过滤。
func (m *Manager) AddToBlacklist(ip string, reason string, duration time.Duration) error {
	return m.AddToBlacklistWithSource(ip, reason, duration, "manual")
}

// AddToBlacklistWithSource adds an IP to the blacklist with a specific source.
// AddToBlacklistWithSource 将 IP 添加到黑名单并指定来源。
// Source can be: "config", "api", "auto", "manual".
// 来源可以是: "config", "api", "auto", "manual".
func (m *Manager) AddToBlacklistWithSource(ip string, reason string, duration time.Duration, source string) error {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return fmt.Errorf("invalid IP address: %v", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	entry := &BlacklistEntry{
		IP:        addr,
		Reason:    reason,
		Source:    source,
		CreatedAt: time.Now(),
	}

	if duration > 0 {
		entry.ExpiresAt = time.Now().Add(duration)
	}

	m.blacklist[addr.String()] = entry

	// Sync to XDP dynamic_blacklist map if callback is set.
	// 如果设置了回调，同步到 XDP dynamic_blacklist Map。
	// Uses SDK's AddDynamicBlacklistIP method internally.
	// 内部使用 SDK 的 AddDynamicBlacklistIP 方法。
	if m.syncToXDPMap != nil {
		if err := m.syncToXDPMap(ip, duration); err != nil {
			m.log.Warnf("Failed to sync %s to XDP dynamic_blacklist: %v", ip, err)
		}
	}

	m.log.Infof("Added %s to real IP blacklist: %s (source: %s)", ip, reason, source)

	return nil
}

// RemoveFromBlacklist removes an IP from the blacklist.
// RemoveFromBlacklist 从黑名单中移除 IP。
// Note: This only removes from local tracking, not from XDP map.
// 注意：这仅从本地跟踪中移除，不会从 XDP Map 中移除。
// Use SDK's RemoveBlacklistIP to remove from XDP map.
// 使用 SDK 的 RemoveBlacklistIP 从 XDP Map 中移除。
func (m *Manager) RemoveFromBlacklist(ip string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.blacklist, ip)
	m.log.Infof("Removed %s from real IP blacklist", ip)

	return nil
}

// IsBlacklisted checks if an IP is blacklisted.
// IsBlacklisted 检查 IP 是否在黑名单中。
func (m *Manager) IsBlacklisted(ip string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	entry, exists := m.blacklist[ip]
	if !exists {
		return false
	}

	// Check if expired.
	// 检查是否过期。
	if !entry.ExpiresAt.IsZero() && time.Now().After(entry.ExpiresAt) {
		return false
	}

	return true
}

// GetRealIPFromLB gets the real client IP for a connection from LB.
// GetRealIPFromLB 获取来自 LB 的连接的真实客户端 IP。
func (m *Manager) GetRealIPFromLB(lbIP string) (netip.Addr, bool) {
	header := m.cache.Get(lbIP)
	if header == nil {
		return netip.Addr{}, false
	}
	return header.SourceIP, true
}

// ShouldDrop determines if a packet should be dropped.
// ShouldDrop 确定是否应该丢弃数据包。
func (m *Manager) ShouldDrop(lbIP string, realIP netip.Addr) (bool, string) {
	// First check if this is from a trusted LB.
	// 首先检查是否来自可信 LB。
	if !m.IsTrustedLB(lbIP) {
		// Not from trusted LB, check if LB IP is blacklisted.
		// 不是来自可信 LB，检查 LB IP 是否在黑名单中。
		if m.IsBlacklisted(lbIP) {
			return true, "lb_blacklisted"
		}
		return false, ""
	}

	// From trusted LB, check real client IP.
	// 来自可信 LB，检查真实客户端 IP。
	if m.IsBlacklisted(realIP.String()) {
		return true, "real_ip_blacklisted"
	}

	return false, ""
}

// CleanupExpired removes expired blacklist entries.
// CleanupExpired 清理过期的黑名单条目。
func (m *Manager) CleanupExpired() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	for ip, entry := range m.blacklist {
		if !entry.ExpiresAt.IsZero() && now.After(entry.ExpiresAt) {
			delete(m.blacklist, ip)
			m.log.Debugf("Removed expired blacklist entry: %s", ip)
		}
	}
}

// ListBlacklist returns all blacklist entries.
// ListBlacklist 返回所有黑名单条目。
func (m *Manager) ListBlacklist() []*BlacklistEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()

	entries := make([]*BlacklistEntry, 0, len(m.blacklist))
	for _, entry := range m.blacklist {
		entries = append(entries, entry)
	}

	return entries
}

// GetStats returns statistics about the manager.
// GetStats 返回管理器的统计信息。
func (m *Manager) GetStats() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return map[string]interface{}{
		"blacklist_count":   len(m.blacklist),
		"whitelist_count":   len(m.whitelist),
		"trusted_lb_ranges": len(m.trustedLBs),
		"proxy_protocol":    m.parser.IsEnabled(),
	}
}

// LoadFromConfig loads blacklist entries from configuration.
// LoadFromConfig 从配置加载黑名单条目。
// This is typically called during initialization to sync config-based blacklist to XDP.
// 这通常在初始化期间调用，以将配置中的黑名单同步到 XDP。
func (m *Manager) LoadFromConfig(entries []BlacklistConfigEntry) error {
	for _, e := range entries {
		duration, err := time.ParseDuration(e.Duration)
		if err != nil {
			m.log.Warnf("Invalid duration for %s: %s, using 24h", e.IP, e.Duration)
			duration = 24 * time.Hour
		}

		if err := m.AddToBlacklistWithSource(e.IP, e.Reason, duration, "config"); err != nil {
			m.log.Warnf("Failed to add %s from config: %v", e.IP, err)
		}
	}

	m.log.Infof("Loaded %d real IP blacklist entries from config", len(entries))
	return nil
}

// BlacklistConfigEntry represents a blacklist entry from configuration.
// BlacklistConfigEntry 表示配置中的黑名单条目。
type BlacklistConfigEntry struct {
	IP       string
	Reason   string
	Duration string
}
