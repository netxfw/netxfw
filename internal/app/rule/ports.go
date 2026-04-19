package rule

import (
	"github.com/netxfw/netxfw/internal/domain/config"
	"github.com/netxfw/netxfw/internal/ports"
	sdk "github.com/netxfw/netxfw/pkg/sdk"
)

type ConfigGateway interface {
	ports.FileWriter
	ports.ConfigWriter
}

type blacklistPort interface {
	Add(cidr string) error
	Remove(cidr string) error
	RemoveDynamic(cidr string) error
	Clear() error
	List(limit int, search string) ([]ports.BlockedIP, int, error)
	ListDynamic(limit int, search string) ([]ports.BlockedIP, int, error)
}

type whitelistPort interface {
	Add(cidr string, port uint16) error
	Remove(cidr string) error
	Clear() error
	List(limit int, search string) ([]string, int, error)
}

type ipPortRulePort interface {
	AddIPPortRule(cidr string, port uint16, action uint8) error
	RemoveIPPortRule(cidr string, port uint16) error
	ListIPPortRules(limit int, search string) ([]config.IPPortRule, int, error)
}

type ruleRuntime interface {
	Blacklist() blacklistPort
	Whitelist() whitelistPort
	Rule() ipPortRulePort
}

type sdkRuntime struct {
	sdk *sdk.SDK
}

func NewRuntime(fw *sdk.SDK) ruleRuntime {
	return sdkRuntime{sdk: fw}
}

func (r sdkRuntime) Blacklist() blacklistPort {
	return blacklistSDKPort{inner: r.sdk.Blacklist}
}

func (r sdkRuntime) Whitelist() whitelistPort {
	return r.sdk.Whitelist
}

func (r sdkRuntime) Rule() ipPortRulePort {
	return ruleSDKPort{inner: r.sdk.Rule}
}

type blacklistSDKPort struct {
	inner interface {
		Add(cidr string) error
		Remove(cidr string) error
		RemoveDynamic(cidr string) error
		Clear() error
		List(limit int, search string) ([]sdk.BlockedIP, int, error)
		ListDynamic(limit int, search string) ([]sdk.BlockedIP, int, error)
	}
}

func (p blacklistSDKPort) Add(cidr string) error           { return p.inner.Add(cidr) }
func (p blacklistSDKPort) Remove(cidr string) error        { return p.inner.Remove(cidr) }
func (p blacklistSDKPort) RemoveDynamic(cidr string) error { return p.inner.RemoveDynamic(cidr) }
func (p blacklistSDKPort) Clear() error                    { return p.inner.Clear() }
func (p blacklistSDKPort) List(limit int, search string) ([]ports.BlockedIP, int, error) {
	items, total, err := p.inner.List(limit, search)
	return ports.BlockedIPsFromSDK(items), total, err
}
func (p blacklistSDKPort) ListDynamic(limit int, search string) ([]ports.BlockedIP, int, error) {
	items, total, err := p.inner.ListDynamic(limit, search)
	return ports.BlockedIPsFromSDK(items), total, err
}

type ruleSDKPort struct {
	inner interface {
		AddIPPortRule(cidr string, port uint16, action uint8) error
		RemoveIPPortRule(cidr string, port uint16) error
		ListIPPortRules(limit int, search string) ([]sdk.IPPortRule, int, error)
	}
}

func (p ruleSDKPort) AddIPPortRule(cidr string, port uint16, action uint8) error {
	return p.inner.AddIPPortRule(cidr, port, action)
}
func (p ruleSDKPort) RemoveIPPortRule(cidr string, port uint16) error {
	return p.inner.RemoveIPPortRule(cidr, port)
}
func (p ruleSDKPort) ListIPPortRules(limit int, search string) ([]config.IPPortRule, int, error) {
	items, total, err := p.inner.ListIPPortRules(limit, search)
	return ports.IPPortRulesFromSDK(items), total, err
}
