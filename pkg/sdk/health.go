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
	Details map[string]interface{}
}

// HealthChecker is an interface for components that can be health-checked.
type HealthChecker interface {
	// Name returns the name of the component.
	Name() string
	// CheckHealth returns the current health status.
	CheckHealth() HealthCheckResult
}
