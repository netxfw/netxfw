package xdp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewHealthChecker(t *testing.T) {
	checker := NewHealthChecker(nil)
	assert.NotNil(t, checker)
	assert.Equal(t, 80, checker.WarningThreshold)
	assert.Equal(t, 95, checker.CriticalThreshold)
}

func TestSetThresholds(t *testing.T) {
	checker := NewHealthChecker(nil)

	checker.SetThresholds(70, 90)
	assert.Equal(t, 70, checker.WarningThreshold)
	assert.Equal(t, 90, checker.CriticalThreshold)

	checker.SetThresholds(-1, 150)
	assert.Equal(t, 70, checker.WarningThreshold)
	assert.Equal(t, 90, checker.CriticalThreshold)

	checker.SetThresholds(0, 0)
	assert.Equal(t, 70, checker.WarningThreshold)
	assert.Equal(t, 90, checker.CriticalThreshold)
}

func TestMapHealthStatus(t *testing.T) {
	status := MapHealthStatus{
		Name:       "test_map",
		Type:       "LRU Hash",
		Entries:    5000,
		MaxEntries: 10000,
		UsagePct:   50,
		Status:     statusOK,
		Message:    "Healthy",
	}

	assert.Equal(t, "test_map", status.Name)
	assert.Equal(t, "LRU Hash", status.Type)
	assert.Equal(t, 5000, status.Entries)
	assert.Equal(t, 10000, status.MaxEntries)
	assert.Equal(t, 50, status.UsagePct)
	assert.Equal(t, statusOK, status.Status)
}

func TestHealthStatus(t *testing.T) {
	status := &HealthStatus{
		BPFMaps: map[string]MapHealthStatus{
			"blacklist": {
				Name:     "blacklist",
				Status:   statusOK,
				Entries:  100,
				UsagePct: 10,
			},
			"whitelist": {
				Name:     "whitelist",
				Status:   statusWarning,
				Entries:  8500,
				UsagePct: 85,
			},
		},
		TotalMaps:     2,
		HealthyMaps:   1,
		WarningMaps:   1,
		CriticalMaps:  0,
		TotalEntries:  8600,
		TotalCapacity: 20000,
		OverallStatus: statusWarning,
	}

	assert.Equal(t, 2, status.TotalMaps)
	assert.Equal(t, 1, status.HealthyMaps)
	assert.Equal(t, 1, status.WarningMaps)
	assert.Equal(t, 0, status.CriticalMaps)
	assert.Equal(t, statusWarning, status.OverallStatus)
}

func TestDetermineOverallStatus(t *testing.T) {
	checker := NewHealthChecker(nil)

	tests := []struct {
		name         string
		criticalMaps int
		warningMaps  int
		expected     string
	}{
		{"all healthy", 0, 0, statusOK},
		{"has warnings", 0, 1, statusWarning},
		{"has critical", 1, 0, statusCritical},
		{"critical takes priority", 1, 2, statusCritical},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status := &HealthStatus{
				CriticalMaps: tt.criticalMaps,
				WarningMaps:  tt.warningMaps,
			}
			checker.determineOverallStatus(status)
			assert.Equal(t, tt.expected, status.OverallStatus)
		})
	}
}

func TestCalculateSummary(t *testing.T) {
	checker := NewHealthChecker(nil)

	status := &HealthStatus{
		BPFMaps: map[string]MapHealthStatus{
			"map1": {Status: statusOK, Entries: 100, MaxEntries: 1000},
			"map2": {Status: statusWarning, Entries: 200, MaxEntries: 2000},
			"map3": {Status: statusCritical, Entries: 300, MaxEntries: 3000},
		},
	}

	checker.calculateSummary(status)

	assert.Equal(t, 3, status.TotalMaps)
	assert.Equal(t, 1, status.HealthyMaps)
	assert.Equal(t, 1, status.WarningMaps)
	assert.Equal(t, 1, status.CriticalMaps)
	assert.Equal(t, 600, status.TotalEntries)
	assert.Equal(t, 6000, status.TotalCapacity)
}

func TestStatusConstants(t *testing.T) {
	assert.Equal(t, "ok", statusOK)
	assert.Equal(t, "warning", statusWarning)
	assert.Equal(t, "critical", statusCritical)
	assert.Equal(t, "unavailable", statusUnavailable)
	assert.Equal(t, "error", statusError)
	assert.Equal(t, "healthy", statusHealthy)
}
