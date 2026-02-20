package xdp

import (
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/livp123/netxfw/internal/utils/fmtutil"
)

// MetricsCollector collects comprehensive firewall metrics.
// MetricsCollector 收集全面的防火墙指标。
type MetricsCollector struct {
	mu sync.RWMutex

	// PPS/BPS metrics / PPS/BPS 指标
	TrafficMetrics TrafficMetrics `json:"traffic_metrics"`

	// Conntrack health / 连接跟踪健康度
	ConntrackHealth ConntrackHealth `json:"conntrack_health"`

	// Map usage statistics / Map 使用率统计
	MapUsage MapUsageStats `json:"map_usage"`

	// Rate limit hit statistics / 限速命中统计
	RateLimitStats RateLimitHitStats `json:"rate_limit_stats"`

	// Protocol distribution / 协议分布
	ProtocolStats ProtocolDistribution `json:"protocol_stats"`

	// Start time / 启动时间
	StartTime time.Time `json:"start_time"`

	// Last update time / 最后更新时间
	LastUpdate time.Time `json:"last_update"`

	// Reference to manager / 管理器引用
	manager *Manager
}

// TrafficMetrics holds PPS/BPS statistics.
// TrafficMetrics 保存 PPS/BPS 统计信息。
type TrafficMetrics struct {
	// Current rates / 当前速率
	CurrentPPS uint64 `json:"current_pps"` // Packets per second / 每秒数据包数
	CurrentBPS uint64 `json:"current_bps"` // Bytes per second / 每秒字节数

	// Peak rates / 峰值速率
	PeakPPS uint64 `json:"peak_pps"` // Peak packets per second / 峰值每秒数据包数
	PeakBPS uint64 `json:"peak_bps"` // Peak bytes per second / 峰值每秒字节数

	// Average rates / 平均速率
	AveragePPS uint64 `json:"average_pps"` // Average packets per second / 平均每秒数据包数
	AverageBPS uint64 `json:"average_bps"` // Average bytes per second / 平均每秒字节数

	// Drop rates / 丢弃速率
	CurrentDropPPS uint64 `json:"current_drop_pps"` // Current drops per second / 当前每秒丢弃数
	PeakDropPPS    uint64 `json:"peak_drop_pps"`    // Peak drops per second / 峰值每秒丢弃数
	TotalDrops     uint64 `json:"total_drops"`      // Total drops / 总丢弃数

	// Pass rates / 通过速率
	CurrentPassPPS uint64 `json:"current_pass_pps"` // Current passes per second / 当前每秒通过数
	PeakPassPPS    uint64 `json:"peak_pass_pps"`    // Peak passes per second / 峰值每秒通过数
	TotalPasses    uint64 `json:"total_passes"`     // Total passes / 总通过数

	// Total counters / 总计数器
	TotalPackets uint64 `json:"total_packets"` // Total packets processed / 处理的总数据包数
	TotalBytes   uint64 `json:"total_bytes"`   // Total bytes processed / 处理的总字节数

	// Previous values for rate calculation / 用于速率计算的前值
	LastPackets uint64    `json:"-"`
	LastBytes   uint64    `json:"-"`
	LastDrops   uint64    `json:"-"`
	LastPasses  uint64    `json:"-"`
	LastTime    time.Time `json:"-"`
}

// ConntrackHealth holds connection tracking health metrics.
// ConntrackHealth 保存连接跟踪健康指标。
type ConntrackHealth struct {
	// Entry counts / 条目计数
	CurrentEntries int `json:"current_entries"` // Current connection entries / 当前连接条目数
	MaxEntries     int `json:"max_entries"`     // Maximum capacity / 最大容量
	UsagePercent   int `json:"usage_percent"`   // Usage percentage / 使用百分比

	// Health status / 健康状态
	Status  string `json:"status"`  // "healthy", "warning", "critical" / 状态
	Message string `json:"message"` // Human-readable message / 人类可读消息

	// Connection statistics / 连接统计
	NewConnections     uint64 `json:"new_connections"`     // New connections / 新连接数
	ExpiredConnections uint64 `json:"expired_connections"` // Expired connections / 过期连接数
	ActiveConnections  uint64 `json:"active_connections"`  // Active connections / 活跃连接数

	// Protocol breakdown / 协议分布
	TCPConnections   uint64 `json:"tcp_connections"`   // TCP connections / TCP 连接数
	UDPConnections   uint64 `json:"udp_connections"`   // UDP connections / UDP 连接数
	ICMPConnections  uint64 `json:"icmp_connections"`  // ICMP connections / ICMP 连接数
	OtherConnections uint64 `json:"other_connections"` // Other connections / 其他连接数

	// Timeouts / 超时设置
	TimeoutSeconds uint64 `json:"timeout_seconds"` // Conntrack timeout / 连接跟踪超时

	// Table efficiency / 表效率
	HashCollisions uint64 `json:"hash_collisions"` // Hash collisions / 哈希冲突
	LookupHits     uint64 `json:"lookup_hits"`     // Lookup hits / 查找命中
	LookupMisses   uint64 `json:"lookup_misses"`   // Lookup misses / 查找未命中
}

// MapUsageStats holds BPF map usage statistics.
// MapUsageStats 保存 BPF Map 使用率统计。
type MapUsageStats struct {
	// Individual map statistics / 单个 Map 统计
	Maps map[string]MapUsageDetail `json:"maps"`

	// Summary statistics / 摘要统计
	TotalMaps     int `json:"total_maps"`     // Total number of maps / Map 总数
	TotalEntries  int `json:"total_entries"`  // Total entries across all maps / 所有 Map 总条目数
	TotalCapacity int `json:"total_capacity"` // Total capacity across all maps / 所有 Map 总容量
	OverallUsage  int `json:"overall_usage"`  // Overall usage percentage / 总体使用百分比
	HealthyMaps   int `json:"healthy_maps"`   // Number of healthy maps / 健康 Map 数量
	WarningMaps   int `json:"warning_maps"`   // Number of warning maps / 警告 Map 数量
	CriticalMaps  int `json:"critical_maps"`  // Number of critical maps / 严重 Map 数量
}

// MapUsageDetail holds detailed usage for a single map.
// MapUsageDetail 保存单个 Map 的详细使用情况。
type MapUsageDetail struct {
	Name       string `json:"name"`        // Map name / Map 名称
	Type       string `json:"type"`        // Map type / Map 类型
	Entries    int    `json:"entries"`     // Current entries / 当前条目数
	MaxEntries int    `json:"max_entries"` // Maximum entries / 最大条目数
	UsagePct   int    `json:"usage_pct"`   // Usage percentage / 使用百分比
	Status     string `json:"status"`      // "ok", "warning", "critical" / 状态
	Message    string `json:"message"`     // Status message / 状态消息
}

// RateLimitHitStats holds rate limit hit statistics.
// RateLimitHitStats 保存限速命中统计。
type RateLimitHitStats struct {
	// Total statistics / 总统计
	TotalRules     int    `json:"total_rules"`      // Total rate limit rules / 总限速规则数
	ActiveRules    int    `json:"active_rules"`     // Active rules / 活跃规则数
	TotalHits      uint64 `json:"total_hits"`       // Total hits / 总命中数
	TotalDropped   uint64 `json:"total_dropped"`    // Total dropped / 总丢弃数
	TotalPassed    uint64 `json:"total_passed"`     // Total passed / 总通过数
	CurrentHitRate string `json:"current_hit_rate"` // Current hit rate / 当前命中率
	AverageHitRate string `json:"average_hit_rate"` // Average hit rate / 平均命中率

	// Top hit rules / 热门命中规则
	TopHitRules []RateLimitRuleHit `json:"top_hit_rules"`

	// Per-rule statistics / 按规则统计
	Rules map[string]RateLimitRuleHit `json:"rules"`
}

// RateLimitRuleHit holds hit statistics for a single rate limit rule.
// RateLimitRuleHit 保存单个限速规则的命中统计。
type RateLimitRuleHit struct {
	CIDR    string `json:"cidr"`     // CIDR range / CIDR 范围
	Rate    uint64 `json:"rate"`     // Rate limit / 速率限制
	Burst   uint64 `json:"burst"`    // Burst limit / 突发限制
	Hits    uint64 `json:"hits"`     // Hit count / 命中次数
	Dropped uint64 `json:"dropped"`  // Dropped count / 丢弃次数
	Passed  uint64 `json:"passed"`   // Passed count / 通过次数
	HitRate string `json:"hit_rate"` // Hit rate percentage / 命中率百分比
	LastHit string `json:"last_hit"` // Last hit time / 最后命中时间
}

// ProtocolDistribution holds protocol distribution statistics.
// ProtocolDistribution 保存协议分布统计。
type ProtocolDistribution struct {
	// Protocol counts / 协议计数
	TCP   ProtocolStats `json:"tcp"`   // TCP statistics / TCP 统计
	UDP   ProtocolStats `json:"udp"`   // UDP statistics / UDP 统计
	ICMP  ProtocolStats `json:"icmp"`  // ICMP statistics / ICMP 统计
	Other ProtocolStats `json:"other"` // Other protocols / 其他协议

	// Total counts / 总计数
	TotalPackets uint64 `json:"total_packets"` // Total packets / 总数据包数
	TotalBytes   uint64 `json:"total_bytes"`   // Total bytes / 总字节数

	// Distribution percentages / 分布百分比
	TCPPct   string `json:"tcp_pct"`   // TCP percentage / TCP 百分比
	UDPPct   string `json:"udp_pct"`   // UDP percentage / UDP 百分比
	ICMPPct  string `json:"icmp_pct"`  // ICMP percentage / ICMP 百分比
	OtherPct string `json:"other_pct"` // Other percentage / 其他百分比
}

// ProtocolStats holds statistics for a single protocol.
// ProtocolStats 保存单个协议的统计信息。
type ProtocolStats struct {
	Packets    uint64 `json:"packets"`    // Packet count / 数据包数
	Bytes      uint64 `json:"bytes"`      // Byte count / 字节数
	Dropped    uint64 `json:"dropped"`    // Dropped count / 丢弃数
	Passed     uint64 `json:"passed"`     // Passed count / 通过数
	Percentage string `json:"percentage"` // Percentage of total / 占总量百分比
}

// MetricsData holds all metrics data without the mutex.
// MetricsData 保存所有指标数据（不含互斥锁）。
type MetricsData struct {
	TrafficMetrics  TrafficMetrics       `json:"traffic_metrics"`
	ConntrackHealth ConntrackHealth      `json:"conntrack_health"`
	MapUsage        MapUsageStats        `json:"map_usage"`
	RateLimitStats  RateLimitHitStats    `json:"rate_limit_stats"`
	ProtocolStats   ProtocolDistribution `json:"protocol_stats"`
	StartTime       time.Time            `json:"start_time"`
	LastUpdate      time.Time            `json:"last_update"`
}

// NewMetricsCollector creates a new metrics collector.
// NewMetricsCollector 创建新的指标收集器。
func NewMetricsCollector(m *Manager) *MetricsCollector {
	return &MetricsCollector{
		StartTime: time.Now(),
		manager:   m,
		MapUsage: MapUsageStats{
			Maps: make(map[string]MapUsageDetail),
		},
		RateLimitStats: RateLimitHitStats{
			Rules:       make(map[string]RateLimitRuleHit),
			TopHitRules: make([]RateLimitRuleHit, 0),
		},
	}
}

// Collect collects all metrics from the manager.
// Collect 从管理器收集所有指标。
func (mc *MetricsCollector) Collect() error {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	mc.LastUpdate = time.Now()

	// Collect traffic metrics / 收集流量指标
	mc.collectTrafficMetrics()

	// Collect conntrack health / 收集连接跟踪健康度
	mc.collectConntrackHealth()

	// Collect map usage / 收集 Map 使用率
	mc.collectMapUsage()

	// Collect rate limit stats / 收集限速统计
	mc.collectRateLimitStats()

	// Collect protocol distribution / 收集协议分布
	mc.collectProtocolStats()

	return nil
}

// collectTrafficMetrics collects PPS/BPS metrics.
// collectTrafficMetrics 收集 PPS/BPS 指标。
func (mc *MetricsCollector) collectTrafficMetrics() {
	if mc.manager == nil {
		return
	}

	// Get current stats from manager / 从管理器获取当前统计
	dropCount, _ := mc.manager.GetDropCount()
	passCount, _ := mc.manager.GetPassCount()
	totalPackets := dropCount + passCount

	// Calculate rates / 计算速率
	now := time.Now()
	if !mc.TrafficMetrics.LastTime.IsZero() {
		elapsed := now.Sub(mc.TrafficMetrics.LastTime).Seconds()
		if elapsed > 0 {
			// Calculate PPS / 计算 PPS
			packetDiff := totalPackets - mc.TrafficMetrics.LastPackets
			mc.TrafficMetrics.CurrentPPS = uint64(float64(packetDiff) / elapsed)

			// Calculate drop/pass rates / 计算丢弃/通过速率
			dropDiff := dropCount - mc.TrafficMetrics.LastDrops
			passDiff := passCount - mc.TrafficMetrics.LastPasses
			mc.TrafficMetrics.CurrentDropPPS = uint64(float64(dropDiff) / elapsed)
			mc.TrafficMetrics.CurrentPassPPS = uint64(float64(passDiff) / elapsed)

			// Estimate BPS (assuming average packet size of 500 bytes) / 估算 BPS（假设平均包大小为 500 字节）
			mc.TrafficMetrics.CurrentBPS = mc.TrafficMetrics.CurrentPPS * 500

			// Update peaks / 更新峰值
			if mc.TrafficMetrics.CurrentPPS > mc.TrafficMetrics.PeakPPS {
				mc.TrafficMetrics.PeakPPS = mc.TrafficMetrics.CurrentPPS
			}
			if mc.TrafficMetrics.CurrentBPS > mc.TrafficMetrics.PeakBPS {
				mc.TrafficMetrics.PeakBPS = mc.TrafficMetrics.CurrentBPS
			}
			if mc.TrafficMetrics.CurrentDropPPS > mc.TrafficMetrics.PeakDropPPS {
				mc.TrafficMetrics.PeakDropPPS = mc.TrafficMetrics.CurrentDropPPS
			}
			if mc.TrafficMetrics.CurrentPassPPS > mc.TrafficMetrics.PeakPassPPS {
				mc.TrafficMetrics.PeakPassPPS = mc.TrafficMetrics.CurrentPassPPS
			}

			// Calculate averages / 计算平均值
			uptime := now.Sub(mc.StartTime).Seconds()
			if uptime > 0 {
				mc.TrafficMetrics.AveragePPS = uint64(float64(totalPackets) / uptime)
				mc.TrafficMetrics.AverageBPS = mc.TrafficMetrics.AveragePPS * 500
			}
		}
	}

	// Update totals / 更新总计
	mc.TrafficMetrics.TotalPackets = totalPackets
	mc.TrafficMetrics.TotalDrops = dropCount
	mc.TrafficMetrics.TotalPasses = passCount
	mc.TrafficMetrics.LastPackets = totalPackets
	mc.TrafficMetrics.LastDrops = dropCount
	mc.TrafficMetrics.LastPasses = passCount
	mc.TrafficMetrics.LastTime = now
}

// collectConntrackHealth collects conntrack health metrics.
// collectConntrackHealth 收集连接跟踪健康指标。
func (mc *MetricsCollector) collectConntrackHealth() {
	if mc.manager == nil || mc.manager.conntrackMap == nil {
		mc.ConntrackHealth.Status = statusUnavailable
		mc.ConntrackHealth.Message = "Conntrack map not initialized / 连接跟踪 Map 未初始化"
		return
	}

	// Get conntrack count / 获取连接跟踪计数
	count, err := mc.manager.GetConntrackCount()
	if err != nil {
		mc.ConntrackHealth.Status = statusError
		mc.ConntrackHealth.Message = "Failed to get conntrack count / 获取连接跟踪计数失败"
		return
	}

	// Get max entries / 获取最大条目数
	maxEntries := int(mc.manager.conntrackMap.MaxEntries())
	mc.ConntrackHealth.MaxEntries = maxEntries
	mc.ConntrackHealth.CurrentEntries = int(count) // #nosec G115 // count is always within int range

	// Calculate usage / 计算使用率
	if maxEntries > 0 {
		mc.ConntrackHealth.UsagePercent = (int(count) * 100) / maxEntries // #nosec G115 // count is always within int range
	}

	// Determine health status / 确定健康状态
	if mc.ConntrackHealth.UsagePercent >= 95 {
		mc.ConntrackHealth.Status = statusCritical
		mc.ConntrackHealth.Message = "Conntrack table near capacity / 连接跟踪表接近容量"
	} else if mc.ConntrackHealth.UsagePercent >= 80 {
		mc.ConntrackHealth.Status = statusWarning
		mc.ConntrackHealth.Message = "Conntrack table usage high / 连接跟踪表使用率较高"
	} else {
		mc.ConntrackHealth.Status = statusHealthy
		mc.ConntrackHealth.Message = "Conntrack table healthy / 连接跟踪表健康"
	}

	// Get conntrack entries for protocol breakdown / 获取连接跟踪条目以进行协议分布
	entries, err := mc.manager.ListConntrackEntries()
	if err == nil {
		mc.ConntrackHealth.ActiveConnections = uint64(len(entries))
		for _, entry := range entries {
			switch entry.Protocol {
			case 6: // TCP
				mc.ConntrackHealth.TCPConnections++
			case 17: // UDP
				mc.ConntrackHealth.UDPConnections++
			case 1: // ICMP
				mc.ConntrackHealth.ICMPConnections++
			default:
				mc.ConntrackHealth.OtherConnections++
			}
		}
	}
}

// collectMapUsage collects BPF map usage statistics.
// collectMapUsage 收集 BPF Map 使用率统计。
func (mc *MetricsCollector) collectMapUsage() {
	if mc.manager == nil {
		return
	}

	// Reset summary / 重置摘要
	mc.MapUsage.TotalMaps = 0
	mc.MapUsage.TotalEntries = 0
	mc.MapUsage.TotalCapacity = 0
	mc.MapUsage.HealthyMaps = 0
	mc.MapUsage.WarningMaps = 0
	mc.MapUsage.CriticalMaps = 0

	// Check each map / 检查每个 Map
	mc.checkMapUsage("static_blacklist", mc.manager.staticBlacklist, "LPM Trie")
	mc.checkMapUsage("dynamic_blacklist", mc.manager.dynamicBlacklist, "LRU Hash")
	mc.checkMapUsage("whitelist", mc.manager.whitelist, "LPM Trie")
	mc.checkMapUsage("conntrack_map", mc.manager.conntrackMap, "Hash")
	mc.checkMapUsage("rule_map", mc.manager.ruleMap, "LPM Trie")
	mc.checkMapUsage("ratelimit_map", mc.manager.ratelimitMap, "Hash")

	// Calculate overall usage / 计算总体使用率
	if mc.MapUsage.TotalCapacity > 0 {
		mc.MapUsage.OverallUsage = (mc.MapUsage.TotalEntries * 100) / mc.MapUsage.TotalCapacity
	}
}

// checkMapUsage checks usage for a single map.
// checkMapUsage 检查单个 Map 的使用情况。
func (mc *MetricsCollector) checkMapUsage(name string, mapObj *ebpf.Map, mapType string) {
	mc.MapUsage.TotalMaps++

	if mapObj == nil {
		mc.MapUsage.Maps[name] = MapUsageDetail{
			Name:    name,
			Type:    mapType,
			Status:  statusUnavailable,
			Message: "Map not initialized / Map 未初始化",
		}
		mc.MapUsage.CriticalMaps++
		return
	}

	maxEntries := int(mapObj.MaxEntries())
	entries, err := countMapEntriesFast(mapObj)
	if err != nil {
		entries = 0
	}

	usagePct := 0
	if maxEntries > 0 {
		usagePct = (entries * 100) / maxEntries
	}

	status := "ok"
	message := "Healthy / 健康"
	if usagePct >= 95 {
		status = "critical"
		message = "Critical usage level / 严重使用级别"
		mc.MapUsage.CriticalMaps++
	} else if usagePct >= 80 {
		status = "warning"
		message = "High usage level / 高使用级别"
		mc.MapUsage.WarningMaps++
	} else {
		mc.MapUsage.HealthyMaps++
	}

	mc.MapUsage.Maps[name] = MapUsageDetail{
		Name:       name,
		Type:       mapType,
		Entries:    entries,
		MaxEntries: maxEntries,
		UsagePct:   usagePct,
		Status:     status,
		Message:    message,
	}

	mc.MapUsage.TotalEntries += entries
	mc.MapUsage.TotalCapacity += maxEntries
}

// collectRateLimitStats collects rate limit hit statistics.
// collectRateLimitStats 收集限速命中统计。
func (mc *MetricsCollector) collectRateLimitStats() {
	if mc.manager == nil || mc.manager.ratelimitMap == nil {
		return
	}

	// Get rate limit rules / 获取限速规则
	rules, _, err := mc.manager.ListRateLimitRules(1000, "")
	if err != nil {
		return
	}

	mc.RateLimitStats.TotalRules = len(rules)
	mc.RateLimitStats.ActiveRules = len(rules)
	mc.RateLimitStats.Rules = make(map[string]RateLimitRuleHit)

	// Calculate hit statistics / 计算命中统计
	// Note: RateLimitConf only has Rate and Burst, no hit statistics
	// 注意：RateLimitConf 只有 Rate 和 Burst，没有命中统计
	for cidr, rule := range rules {
		hit := RateLimitRuleHit{
			CIDR:    cidr,
			Rate:    rule.Rate,
			Burst:   rule.Burst,
			Hits:    0, // Not tracked in current implementation / 当前实现中未跟踪
			Dropped: 0, // Not tracked in current implementation / 当前实现中未跟踪
			Passed:  0, // Not tracked in current implementation / 当前实现中未跟踪
			HitRate: "N/A",
			LastHit: time.Now().Format(time.RFC3339),
		}

		mc.RateLimitStats.Rules[cidr] = hit
	}

	// Total hits not available in current implementation / 当前实现中没有总命中数
	mc.RateLimitStats.TotalHits = 0
	mc.RateLimitStats.CurrentHitRate = "N/A"
	mc.RateLimitStats.AverageHitRate = "N/A"
}

// collectProtocolStats collects protocol distribution statistics.
// collectProtocolStats 收集协议分布统计。
func (mc *MetricsCollector) collectProtocolStats() {
	if mc.manager == nil {
		return
	}

	// Get drop and pass details for protocol analysis / 获取丢弃和通过详情以进行协议分析
	dropDetails, _ := mc.manager.GetDropDetails()
	passDetails, _ := mc.manager.GetPassDetails()

	// Reset protocol stats / 重置协议统计
	mc.ProtocolStats = ProtocolDistribution{
		TotalPackets: mc.TrafficMetrics.TotalPackets,
		TotalBytes:   mc.TrafficMetrics.TotalBytes,
	}

	// Analyze drop details / 分析丢弃详情
	for _, detail := range dropDetails {
		switch detail.Protocol {
		case 6: // TCP
			mc.ProtocolStats.TCP.Packets += detail.Count
			mc.ProtocolStats.TCP.Dropped += detail.Count
		case 17: // UDP
			mc.ProtocolStats.UDP.Packets += detail.Count
			mc.ProtocolStats.UDP.Dropped += detail.Count
		case 1: // ICMP
			mc.ProtocolStats.ICMP.Packets += detail.Count
			mc.ProtocolStats.ICMP.Dropped += detail.Count
		default:
			mc.ProtocolStats.Other.Packets += detail.Count
			mc.ProtocolStats.Other.Dropped += detail.Count
		}
	}

	// Analyze pass details / 分析通过详情
	for _, detail := range passDetails {
		switch detail.Protocol {
		case 6: // TCP
			mc.ProtocolStats.TCP.Packets += detail.Count
			mc.ProtocolStats.TCP.Passed += detail.Count
		case 17: // UDP
			mc.ProtocolStats.UDP.Packets += detail.Count
			mc.ProtocolStats.UDP.Passed += detail.Count
		case 1: // ICMP
			mc.ProtocolStats.ICMP.Packets += detail.Count
			mc.ProtocolStats.ICMP.Passed += detail.Count
		default:
			mc.ProtocolStats.Other.Packets += detail.Count
			mc.ProtocolStats.Other.Passed += detail.Count
		}
	}

	// Calculate percentages / 计算百分比
	total := mc.ProtocolStats.TCP.Packets + mc.ProtocolStats.UDP.Packets +
		mc.ProtocolStats.ICMP.Packets + mc.ProtocolStats.Other.Packets

	if total > 0 {
		mc.ProtocolStats.TCPPct = fmtutil.FormatPercent(float64(mc.ProtocolStats.TCP.Packets) / float64(total) * 100)
		mc.ProtocolStats.UDPPct = fmtutil.FormatPercent(float64(mc.ProtocolStats.UDP.Packets) / float64(total) * 100)
		mc.ProtocolStats.ICMPPct = fmtutil.FormatPercent(float64(mc.ProtocolStats.ICMP.Packets) / float64(total) * 100)
		mc.ProtocolStats.OtherPct = fmtutil.FormatPercent(float64(mc.ProtocolStats.Other.Packets) / float64(total) * 100)

		mc.ProtocolStats.TCP.Percentage = mc.ProtocolStats.TCPPct
		mc.ProtocolStats.UDP.Percentage = mc.ProtocolStats.UDPPct
		mc.ProtocolStats.ICMP.Percentage = mc.ProtocolStats.ICMPPct
		mc.ProtocolStats.Other.Percentage = mc.ProtocolStats.OtherPct
	}
}

// GetMetrics returns current metrics data.
// GetMetrics 返回当前指标数据。
func (mc *MetricsCollector) GetMetrics() *MetricsData {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	// Return a copy without mutex / 返回不含互斥锁的副本
	return &MetricsData{
		TrafficMetrics:  mc.TrafficMetrics,
		ConntrackHealth: mc.ConntrackHealth,
		MapUsage:        mc.MapUsage,
		RateLimitStats:  mc.RateLimitStats,
		ProtocolStats:   mc.ProtocolStats,
		StartTime:       mc.StartTime,
		LastUpdate:      mc.LastUpdate,
	}
}

// GetTrafficMetrics returns traffic metrics.
// GetTrafficMetrics 返回流量指标。
func (mc *MetricsCollector) GetTrafficMetrics() TrafficMetrics {
	mc.mu.RLock()
	defer mc.mu.RUnlock()
	return mc.TrafficMetrics
}

// GetConntrackHealth returns conntrack health.
// GetConntrackHealth 返回连接跟踪健康度。
func (mc *MetricsCollector) GetConntrackHealth() ConntrackHealth {
	mc.mu.RLock()
	defer mc.mu.RUnlock()
	return mc.ConntrackHealth
}

// GetMapUsage returns map usage statistics.
// GetMapUsage 返回 Map 使用率统计。
func (mc *MetricsCollector) GetMapUsage() MapUsageStats {
	mc.mu.RLock()
	defer mc.mu.RUnlock()
	return mc.MapUsage
}

// GetRateLimitStats returns rate limit statistics.
// GetRateLimitStats 返回限速统计。
func (mc *MetricsCollector) GetRateLimitStats() RateLimitHitStats {
	mc.mu.RLock()
	defer mc.mu.RUnlock()
	return mc.RateLimitStats
}

// GetProtocolStats returns protocol distribution.
// GetProtocolStats 返回协议分布。
func (mc *MetricsCollector) GetProtocolStats() ProtocolDistribution {
	mc.mu.RLock()
	defer mc.mu.RUnlock()
	return mc.ProtocolStats
}

// countMapEntriesFast counts entries in a map quickly.
// countMapEntriesFast 快速计算 Map 中的条目数。
func countMapEntriesFast(m *ebpf.Map) (int, error) {
	if m == nil {
		return 0, nil
	}

	var count int
	var key []byte
	var value []byte

	iter := m.Iterate()
	for iter.Next(&key, &value) {
		count++
	}

	return count, iter.Err()
}
