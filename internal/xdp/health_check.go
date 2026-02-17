package xdp

import (
	"fmt"
	"time"

	"github.com/cilium/ebpf"
)

// MapHealthStatus represents the health status of a single BPF map.
// MapHealthStatus 表示单个 BPF Map 的健康状态。
type MapHealthStatus struct {
	Name       string `json:"name"`        // Map name / Map 名称
	Type       string `json:"type"`        // Map type (hash, lru, lpm_trie, etc.) / Map 类型
	Entries    int    `json:"entries"`     // Current number of entries / 当前条目数
	MaxEntries int    `json:"max_entries"` // Maximum capacity / 最大容量
	UsagePct   int    `json:"usage_pct"`   // Usage percentage / 使用百分比
	Status     string `json:"status"`      // "ok", "warning", "critical" / 状态
	Message    string `json:"message"`     // Human-readable status message / 人类可读的状态消息
}

// HealthStatus represents the overall health status of the firewall.
// HealthStatus 表示防火墙的整体健康状态。
type HealthStatus struct {
	Timestamp time.Time `json:"timestamp"` // Check timestamp / 检查时间戳
	Uptime    string    `json:"uptime"`    // Service uptime / 服务运行时间

	// BPF Maps health / BPF Map 健康状态
	BPFMaps map[string]MapHealthStatus `json:"bpf_maps"`

	// Overall status / 整体状态
	OverallStatus string `json:"overall_status"` // "ok", "warning", "critical"

	// Summary statistics / 摘要统计
	TotalMaps     int `json:"total_maps"`     // Total number of maps / Map 总数
	HealthyMaps   int `json:"healthy_maps"`   // Number of healthy maps / 健康 Map 数量
	WarningMaps   int `json:"warning_maps"`   // Number of warning maps / 警告 Map 数量
	CriticalMaps  int `json:"critical_maps"`  // Number of critical maps / 严重 Map 数量
	TotalEntries  int `json:"total_entries"`  // Total entries across all maps / 所有 Map 的总条目数
	TotalCapacity int `json:"total_capacity"` // Total capacity across all maps / 所有 Map 的总容量

	// Error information / 错误信息
	Errors []string `json:"errors,omitempty"` // List of errors encountered / 遇到的错误列表
}

// HealthChecker provides health checking functionality for BPF maps.
// HealthChecker 提供 BPF Map 健康检查功能。
type HealthChecker struct {
	manager *Manager

	// Thresholds for status determination / 状态判定阈值
	WarningThreshold  int // Usage percentage for warning status / 警告状态的使用百分比
	CriticalThreshold int // Usage percentage for critical status / 严重状态的使用百分比
}

// NewHealthChecker creates a new health checker.
// NewHealthChecker 创建新的健康检查器。
func NewHealthChecker(m *Manager) *HealthChecker {
	return &HealthChecker{
		manager:           m,
		WarningThreshold:  80, // 80% usage triggers warning / 80% 使用率触发警告
		CriticalThreshold: 95, // 95% usage triggers critical / 95% 使用率触发严重
	}
}

// SetThresholds sets custom thresholds for health status determination.
// SetThresholds 设置健康状态判定的自定义阈值。
func (h *HealthChecker) SetThresholds(warning, critical int) {
	if warning > 0 && warning < 100 {
		h.WarningThreshold = warning
	}
	if critical > 0 && critical < 100 {
		h.CriticalThreshold = critical
	}
}

// CheckHealth performs a comprehensive health check of all BPF maps.
// CheckHealth 对所有 BPF Map 执行全面健康检查。
func (h *HealthChecker) CheckHealth() *HealthStatus {
	status := &HealthStatus{
		Timestamp:     time.Now(),
		BPFMaps:       make(map[string]MapHealthStatus),
		OverallStatus: "ok",
		Errors:        []string{},
	}

	// Calculate uptime / 计算运行时间
	if h.manager.perfStats != nil {
		uptime := time.Since(h.manager.perfStats.StartTime)
		status.Uptime = uptime.Round(time.Second).String()
	}

	// Check each map / 检查每个 Map
	h.checkMap("static_blacklist", h.manager.staticBlacklist, "LPM Trie", status)
	h.checkMap("dynamic_blacklist", h.manager.dynamicBlacklist, "LRU Hash", status)
	h.checkMap("whitelist", h.manager.whitelist, "LPM Trie", status)
	h.checkMap("conntrack_map", h.manager.conntrackMap, "Hash", status)
	h.checkMap("rule_map", h.manager.ruleMap, "LPM Trie", status)

	// Calculate summary statistics / 计算摘要统计
	h.calculateSummary(status)

	// Determine overall status / 确定整体状态
	h.determineOverallStatus(status)

	return status
}

// checkMap checks the health of a single BPF map.
// checkMap 检查单个 BPF Map 的健康状态。
func (h *HealthChecker) checkMap(name string, mapObj *ebpf.Map, mapType string, status *HealthStatus) {
	if mapObj == nil {
		status.BPFMaps[name] = MapHealthStatus{
			Name:    name,
			Type:    mapType,
			Status:  "critical",
			Message: "Map not initialized / Map 未初始化",
		}
		status.Errors = append(status.Errors, fmt.Sprintf("%s: map not initialized", name))
		return
	}

	// Get map info / 获取 Map 信息
	maxEntries := int(mapObj.MaxEntries())
	entries, err := h.countMapEntries(mapObj)
	if err != nil {
		status.BPFMaps[name] = MapHealthStatus{
			Name:       name,
			Type:       mapType,
			MaxEntries: maxEntries,
			Status:     "warning",
			Message:    fmt.Sprintf("Failed to get entry count: %v / 获取条目数失败: %v", err, err),
		}
		status.Errors = append(status.Errors, fmt.Sprintf("%s: failed to get entries: %v", name, err))
		return
	}

	// Calculate usage percentage / 计算使用百分比
	usagePct := 0
	if maxEntries > 0 {
		usagePct = (entries * 100) / maxEntries
	}

	// Determine status based on thresholds / 根据阈值确定状态
	mapStatus := "ok"
	message := "Healthy / 健康"

	if usagePct >= h.CriticalThreshold {
		mapStatus = "critical"
		message = fmt.Sprintf("Critical: %d%% capacity used / 严重: 已使用 %d%% 容量", usagePct, usagePct)
	} else if usagePct >= h.WarningThreshold {
		mapStatus = "warning"
		message = fmt.Sprintf("Warning: %d%% capacity used / 警告: 已使用 %d%% 容量", usagePct, usagePct)
	}

	status.BPFMaps[name] = MapHealthStatus{
		Name:       name,
		Type:       mapType,
		Entries:    entries,
		MaxEntries: maxEntries,
		UsagePct:   usagePct,
		Status:     mapStatus,
		Message:    message,
	}
}

// countMapEntries counts the number of entries in a map by iteration.
// countMapEntries 通过迭代计算 Map 中的条目数。
func (h *HealthChecker) countMapEntries(mapObj *ebpf.Map) (int, error) {
	if mapObj == nil {
		return 0, fmt.Errorf("map is nil")
	}

	iter := mapObj.Iterate()
	count := 0

	var key, val interface{}
	for iter.Next(&key, &val) {
		count++
	}

	if err := iter.Err(); err != nil {
		return count, err
	}

	return count, nil
}

// calculateSummary calculates summary statistics from the health check results.
// calculateSummary 从健康检查结果计算摘要统计。
func (h *HealthChecker) calculateSummary(status *HealthStatus) {
	status.TotalMaps = len(status.BPFMaps)

	for _, mapStatus := range status.BPFMaps {
		status.TotalEntries += mapStatus.Entries
		status.TotalCapacity += mapStatus.MaxEntries

		switch mapStatus.Status {
		case "ok":
			status.HealthyMaps++
		case "warning":
			status.WarningMaps++
		case "critical":
			status.CriticalMaps++
		}
	}
}

// determineOverallStatus determines the overall health status.
// determineOverallStatus 确定整体健康状态。
func (h *HealthChecker) determineOverallStatus(status *HealthStatus) {
	if status.CriticalMaps > 0 {
		status.OverallStatus = "critical"
	} else if status.WarningMaps > 0 {
		status.OverallStatus = "warning"
	} else {
		status.OverallStatus = "ok"
	}
}

// CheckMapHealth checks the health of a specific map.
// CheckMapHealth 检查特定 Map 的健康状态。
func (h *HealthChecker) CheckMapHealth(mapName string) (*MapHealthStatus, error) {
	fullStatus := h.CheckHealth()
	mapStatus, exists := fullStatus.BPFMaps[mapName]
	if !exists {
		return nil, fmt.Errorf("map not found: %s", mapName)
	}
	return &mapStatus, nil
}

// GetMapUsage returns the usage percentage of a specific map.
// GetMapUsage 返回特定 Map 的使用百分比。
func (h *HealthChecker) GetMapUsage(mapName string) (int, error) {
	mapStatus, err := h.CheckMapHealth(mapName)
	if err != nil {
		return 0, err
	}
	return mapStatus.UsagePct, nil
}

// IsHealthy returns true if all maps are healthy.
// IsHealthy 如果所有 Map 都健康则返回 true。
func (h *HealthChecker) IsHealthy() bool {
	status := h.CheckHealth()
	return status.OverallStatus == "ok"
}

// HasWarnings returns true if there are any warnings.
// HasWarnings 如果有任何警告则返回 true。
func (h *HealthChecker) HasWarnings() bool {
	status := h.CheckHealth()
	return status.WarningMaps > 0 || status.CriticalMaps > 0
}

// GetCriticalMaps returns a list of maps in critical state.
// GetCriticalMaps 返回处于严重状态的 Map 列表。
func (h *HealthChecker) GetCriticalMaps() []string {
	status := h.CheckHealth()
	var critical []string
	for name, mapStatus := range status.BPFMaps {
		if mapStatus.Status == "critical" {
			critical = append(critical, name)
		}
	}
	return critical
}

// GetWarningMaps returns a list of maps in warning state.
// GetWarningMaps 返回处于警告状态的 Map 列表。
func (h *HealthChecker) GetWarningMaps() []string {
	status := h.CheckHealth()
	var warnings []string
	for name, mapStatus := range status.BPFMaps {
		if mapStatus.Status == "warning" {
			warnings = append(warnings, name)
		}
	}
	return warnings
}
