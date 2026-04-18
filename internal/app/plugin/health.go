package plugin

import "github.com/netxfw/netxfw/pkg/sdk"

// HealthSnapshot captures aggregated runtime/datapath plugin health.
type HealthSnapshot struct {
	Runtime  sdk.HealthCheckResult
	Datapath sdk.HealthCheckResult
}

// SummarizeHealth converts unified plugin status into aggregated health results.
func SummarizeHealth(snapshot StatusSnapshot) HealthSnapshot {
	return HealthSnapshot{
		Runtime:  summarizeRuntimeHealth(snapshot),
		Datapath: summarizeDatapathHealth(snapshot),
	}
}

func summarizeRuntimeHealth(snapshot StatusSnapshot) sdk.HealthCheckResult {
	if len(snapshot.Runtime) == 0 {
		return sdk.HealthCheckResult{
			Status:  sdk.HealthStatusHealthy,
			Message: "no runtime plugins registered",
			Details: map[string]any{"total": 0, "enabled": 0},
		}
	}

	enabled := 0
	unhealthy := 0
	running := 0
	status := sdk.HealthStatusHealthy
	for _, item := range snapshot.Runtime {
		if item.Enabled {
			enabled++
		}
		if item.Running {
			running++
		}
		if item.Enabled && !item.Healthy {
			unhealthy++
			status = sdk.CombineHealthStatuses(status, sdk.HealthStatusUnhealthy)
		}
	}

	message := "all enabled runtime plugins healthy"
	switch {
	case enabled == 0:
		message = "no runtime plugins enabled"
	case unhealthy > 0:
		message = "runtime plugin configuration issues detected"
	case running < enabled:
		status = sdk.CombineHealthStatuses(status, sdk.HealthStatusDegraded)
		message = "some enabled runtime plugins are not running"
	}

	return sdk.HealthCheckResult{
		Status:  status,
		Message: message,
		Details: map[string]any{
			"total":     len(snapshot.Runtime),
			"enabled":   enabled,
			"running":   running,
			"unhealthy": unhealthy,
		},
	}
}

func summarizeDatapathHealth(snapshot StatusSnapshot) sdk.HealthCheckResult {
	if len(snapshot.Datapath) == 0 {
		return sdk.HealthCheckResult{
			Status:  sdk.HealthStatusHealthy,
			Message: "no datapath plugins configured",
			Details: map[string]any{"total": 0, "loaded": 0},
		}
	}

	loaded := 0
	unhealthy := 0
	status := sdk.HealthStatusHealthy
	for _, item := range snapshot.Datapath {
		if item.Loaded {
			loaded++
		}
		if !item.Healthy {
			unhealthy++
			status = sdk.CombineHealthStatuses(status, sdk.HealthStatusDegraded)
		}
	}

	message := "all datapath plugins loaded"
	if unhealthy > 0 {
		message = "datapath plugin drift detected"
	}

	return sdk.HealthCheckResult{
		Status:  status,
		Message: message,
		Details: map[string]any{
			"total":     len(snapshot.Datapath),
			"loaded":    loaded,
			"unhealthy": unhealthy,
		},
	}
}
