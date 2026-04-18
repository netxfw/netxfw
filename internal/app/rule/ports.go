package rule

import (
	"os"

	"github.com/netxfw/netxfw/pkg/sdk"
)

type ConfigGateway interface {
	WriteFile(path string, data []byte, perm os.FileMode, source string) error
	SaveGlobalConfig(path string, cfg *sdk.GlobalConfig, keepBackups int, source string) error
}

type blacklistPort interface {
	Add(cidr string) error
	Remove(cidr string) error
	RemoveDynamic(cidr string) error
	Clear() error
}

type whitelistPort interface {
	Add(cidr string, port uint16) error
	Remove(cidr string) error
	Clear() error
}

type ipPortRulePort interface {
	AddIPPortRule(cidr string, port uint16, action uint8) error
	RemoveIPPortRule(cidr string, port uint16) error
	ListIPPortRules(limit int, search string) ([]sdk.IPPortRule, int, error)
}

type ruleRuntime interface {
	Blacklist() blacklistPort
	Whitelist() whitelistPort
	Rule() ipPortRulePort
	Manager() sdk.ManagerInterface
}

type sdkRuntime struct {
	sdk *sdk.SDK
}

func NewRuntime(fw *sdk.SDK) ruleRuntime {
	return sdkRuntime{sdk: fw}
}

func (r sdkRuntime) Blacklist() blacklistPort {
	return r.sdk.Blacklist
}

func (r sdkRuntime) Whitelist() whitelistPort {
	return r.sdk.Whitelist
}

func (r sdkRuntime) Rule() ipPortRulePort {
	return r.sdk.Rule
}

func (r sdkRuntime) Manager() sdk.ManagerInterface {
	return r.sdk.GetManager()
}
