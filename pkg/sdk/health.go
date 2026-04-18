package sdk

// HealthStatus represents the health status of a component.
type HealthStatus string

const (
	HealthStatusHealthy   HealthStatus = "healthy"
	HealthStatusDegraded  HealthStatus = "degraded"
	HealthStatusUnhealthy HealthStatus = "unhealthy"
)

// HealthCheckResult contains the result of a health check.
type HealthCheckResult struct {
	Status  HealthStatus
	Message string
	Details map[string]any
}

// CombineHealthStatuses returns the worst status from the provided statuses.
func CombineHealthStatuses(statuses ...HealthStatus) HealthStatus {
	combined := HealthStatusHealthy
	for _, status := range statuses {
		if healthSeverity(status) > healthSeverity(combined) {
			combined = status
		}
	}
	return combined
}

// HealthChecker is an interface for components that can be health-checked.
type HealthChecker interface {
	// Name returns the name of the component.
	Name() string
	// CheckHealth returns the current health status.
	CheckHealth() HealthCheckResult
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
