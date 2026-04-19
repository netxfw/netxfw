package ports

// HealthStatus represents component health at internal boundaries.
type HealthStatus string

const (
	HealthStatusHealthy   HealthStatus = "healthy"
	HealthStatusDegraded  HealthStatus = "degraded"
	HealthStatusUnhealthy HealthStatus = "unhealthy"
)

// HealthCheckResult captures internal health summaries.
type HealthCheckResult struct {
	Status  HealthStatus
	Message string
	Details map[string]any
}

// CombineHealthStatuses keeps the app boundary independent from direct sdk imports at call sites.
func CombineHealthStatuses(statuses ...HealthStatus) HealthStatus {
	combined := HealthStatusHealthy
	for _, status := range statuses {
		if healthSeverity(status) > healthSeverity(combined) {
			combined = status
		}
	}
	return combined
}

func healthSeverity(status HealthStatus) int {
	switch status {
	case HealthStatusUnhealthy:
		return 2
	case HealthStatusDegraded:
		return 1
	default:
		return 0
	}
}
