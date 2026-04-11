package services

import (
	"github.com/netxfw/netxfw/internal/app"
	"github.com/netxfw/netxfw/pkg/sdk"
)

// RuleCommandService centralizes rule command operations used by CLI.
type RuleCommandService struct{}

func NewRuleCommandService() *RuleCommandService {
	return &RuleCommandService{}
}

// RuleAction identifies allow/deny semantics for command-layer flows.
type RuleAction uint8

const (
	RuleActionDeny RuleAction = iota
	RuleActionAllow
)

func (s *RuleCommandService) AddRule(fw *sdk.SDK, ip string, port uint16, action RuleAction) error {
	if action == RuleActionAllow {
		return app.AddRule(fw, ip, port, app.RuleActionAllow)
	}
	return app.AddRule(fw, ip, port, app.RuleActionDeny)
}

func (s *RuleCommandService) AddAllowRule(fw *sdk.SDK, ip string, port uint16) error {
	return s.AddRule(fw, ip, port, RuleActionAllow)
}

func (s *RuleCommandService) AddDenyRule(fw *sdk.SDK, ip string, port uint16) error {
	return s.AddRule(fw, ip, port, RuleActionDeny)
}

func (s *RuleCommandService) DeleteRule(cfg *sdk.GlobalConfig, fw *sdk.SDK, ip string, port uint16) (bool, error) {
	return app.DeleteRule(cfg, fw, ip, port)
}

func (s *RuleCommandService) DeleteFromAllRuleStores(fw *sdk.SDK, ip string, port uint16) []string {
	return app.DeleteFromAllRuleStores(fw, ip, port)
}

func (s *RuleCommandService) ParseIPPort(input string) (string, uint16, error) {
	return app.ParseIPPort(input)
}

func (s *RuleCommandService) IsValidCIDR(input string) bool {
	return app.IsValidCIDR(input)
}
