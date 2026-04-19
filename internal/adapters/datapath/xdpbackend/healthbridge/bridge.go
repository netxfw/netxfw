package healthbridge

import (
	xdpbackend "github.com/netxfw/netxfw/internal/adapters/datapath/xdpbackend"
	backendxdp "github.com/netxfw/netxfw/internal/datapath/xdp/backend"
	"time"
)

type Manager = xdpbackend.Handle

type MapStatus struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	Entries    int    `json:"entries"`
	MaxEntries int    `json:"max_entries"`
	UsagePct   int    `json:"usage_pct"`
	Status     string `json:"status"`
	Message    string `json:"message"`
}

type Status struct {
	Timestamp     time.Time            `json:"timestamp"`
	Uptime        string               `json:"uptime"`
	BPFMaps       map[string]MapStatus `json:"bpf_maps"`
	OverallStatus string               `json:"overall_status"`
	TotalMaps     int                  `json:"total_maps"`
	HealthyMaps   int                  `json:"healthy_maps"`
	WarningMaps   int                  `json:"warning_maps"`
	CriticalMaps  int                  `json:"critical_maps"`
	TotalEntries  int                  `json:"total_entries"`
	TotalCapacity int                  `json:"total_capacity"`
	Errors        []string             `json:"errors,omitempty"`
}

type Checker struct {
	inner *backendxdp.HealthChecker
}

func NewHealthChecker(manager *Manager) *Checker {
	if manager == nil {
		return nil
	}
	return &Checker{inner: backendxdp.NewHealthChecker(manager.BackendManager())}
}

func (c *Checker) CheckHealth() *Status {
	if c == nil || c.inner == nil {
		return nil
	}
	return convertStatus(c.inner.CheckHealth())
}

func (c *Checker) CheckMapHealth(mapName string) (*MapStatus, error) {
	if c == nil || c.inner == nil {
		return nil, nil
	}
	status, err := c.inner.CheckMapHealth(mapName)
	if err != nil {
		return nil, err
	}
	return convertMapStatus(status), nil
}

func (c *Checker) GetMapUsage(mapName string) (int, error) {
	if c == nil || c.inner == nil {
		return 0, nil
	}
	return c.inner.GetMapUsage(mapName)
}

func (c *Checker) IsHealthy() bool {
	return c != nil && c.inner != nil && c.inner.IsHealthy()
}

func (c *Checker) HasWarnings() bool {
	return c != nil && c.inner != nil && c.inner.HasWarnings()
}

func (c *Checker) GetCriticalMaps() []string {
	if c == nil || c.inner == nil {
		return nil
	}
	return c.inner.GetCriticalMaps()
}

func (c *Checker) GetWarningMaps() []string {
	if c == nil || c.inner == nil {
		return nil
	}
	return c.inner.GetWarningMaps()
}

func convertStatus(status *backendxdp.HealthStatus) *Status {
	if status == nil {
		return nil
	}

	convertedMaps := make(map[string]MapStatus, len(status.BPFMaps))
	for name, mapStatus := range status.BPFMaps {
		convertedMaps[name] = MapStatus{
			Name:       mapStatus.Name,
			Type:       mapStatus.Type,
			Entries:    mapStatus.Entries,
			MaxEntries: mapStatus.MaxEntries,
			UsagePct:   mapStatus.UsagePct,
			Status:     mapStatus.Status,
			Message:    mapStatus.Message,
		}
	}

	return &Status{
		Timestamp:     status.Timestamp,
		Uptime:        status.Uptime,
		BPFMaps:       convertedMaps,
		OverallStatus: status.OverallStatus,
		TotalMaps:     status.TotalMaps,
		HealthyMaps:   status.HealthyMaps,
		WarningMaps:   status.WarningMaps,
		CriticalMaps:  status.CriticalMaps,
		TotalEntries:  status.TotalEntries,
		TotalCapacity: status.TotalCapacity,
		Errors:        append([]string(nil), status.Errors...),
	}
}

func convertMapStatus(status *backendxdp.MapHealthStatus) *MapStatus {
	if status == nil {
		return nil
	}
	return &MapStatus{
		Name:       status.Name,
		Type:       status.Type,
		Entries:    status.Entries,
		MaxEntries: status.MaxEntries,
		UsagePct:   status.UsagePct,
		Status:     status.Status,
		Message:    status.Message,
	}
}
