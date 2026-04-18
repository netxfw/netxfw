package config

import (
	"context"
	"fmt"

	"github.com/netxfw/netxfw/internal/utils/logger"
	"github.com/netxfw/netxfw/pkg/sdk"
)

func ReconcileConfigToRuntime(ctx context.Context, mgr sdk.ManagerInterface, cfg *sdk.GlobalConfig) (Plan, error) {
	plan := NewPlanner().PlanConfigToRuntime(cfg, mgr)
	logPlan(ctx, plan)
	if err := NewExecutor().Execute(plan, mgr, cfg); err != nil {
		return plan, fmt.Errorf("reconcile config to runtime: %w", err)
	}
	return plan, nil
}

func ReconcileRuntimeToConfig(ctx context.Context, mgr sdk.ManagerInterface, cfg *sdk.GlobalConfig) (Plan, error) {
	plan := NewPlanner().PlanRuntimeToConfig(mgr)
	logPlan(ctx, plan)
	if err := NewExecutor().Execute(plan, mgr, cfg); err != nil {
		return plan, fmt.Errorf("reconcile runtime to config: %w", err)
	}
	return plan, nil
}

func VerifyAndRepair(ctx context.Context, mgr sdk.ManagerInterface, cfg *sdk.GlobalConfig) (Plan, error) {
	plan := NewPlanner().PlanVerifyAndRepair(cfg, mgr)
	logPlan(ctx, plan)
	if err := NewExecutor().Execute(plan, mgr, cfg); err != nil {
		return plan, fmt.Errorf("verify and repair runtime: %w", err)
	}
	return plan, nil
}

func logPlan(ctx context.Context, plan Plan) {
	log := logger.Get(ctx)
	switch plan.Mode {
	case ModeConfigToRuntime, ModeVerifyAndRepair:
		log.Infof("[RELOAD] Reconcile plan=%s drift=%d whitelist=%d ports=%d ip_port_rules=%d rate_limits=%d overwrite=%t",
			plan.Mode, len(plan.Drift.Mismatches), plan.Desired.WhitelistCount, plan.Desired.AllowedPortCount,
			plan.Desired.IPPortRuleCount, plan.Desired.RateLimitRuleCount, plan.Overwrite)
	case ModeRuntimeToConfig:
		log.Infof("[SAVE] Reconcile plan=%s locked=%d whitelist=%d ports=%d ip_port_rules=%d rate_limits=%d",
			plan.Mode, plan.Actual.LockedCount.Value, plan.Actual.WhitelistCount.Value, plan.Actual.AllowedPortCount.Value,
			plan.Actual.IPPortRuleCount.Value, plan.Actual.RateLimitRuleCount.Value)
	}
}
