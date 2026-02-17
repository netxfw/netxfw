package sdk

// ruleImpl implements RuleAPI interface.
// ruleImpl 实现 RuleAPI 接口。
type ruleImpl struct {
	mgr ManagerInterface
}

func (r *ruleImpl) Add(cidr string, port uint16, action uint8) error {
	return r.mgr.AddIPPortRule(cidr, port, action)
}

func (r *ruleImpl) Remove(cidr string, port uint16) error {
	return r.mgr.RemoveIPPortRule(cidr, port)
}

func (r *ruleImpl) Clear() error {
	return r.mgr.ClearIPPortRules()
}

func (r *ruleImpl) List(isIPv6 bool, limit int, search string) ([]IPPortRule, int, error) {
	return r.mgr.ListIPPortRules(isIPv6, limit, search)
}

func (r *ruleImpl) AddIPPortRule(cidr string, port uint16, action uint8) error {
	return r.mgr.AddIPPortRule(cidr, port, action)
}

func (r *ruleImpl) RemoveIPPortRule(cidr string, port uint16) error {
	return r.mgr.RemoveIPPortRule(cidr, port)
}

func (r *ruleImpl) ListIPPortRules(limit int, search string) ([]IPPortRule, int, error) {
	return r.mgr.ListIPPortRules(false, limit, search)
}

func (r *ruleImpl) AllowPort(port uint16) error {
	return r.mgr.AllowPort(port)
}

func (r *ruleImpl) RemoveAllowedPort(port uint16) error {
	return r.mgr.RemoveAllowedPort(port)
}

func (r *ruleImpl) AddRateLimitRule(ip string, rate, burst uint64) error {
	return r.mgr.AddRateLimitRule(ip, rate, burst)
}

func (r *ruleImpl) RemoveRateLimitRule(ip string) error {
	return r.mgr.RemoveRateLimitRule(ip)
}

func (r *ruleImpl) ListRateLimitRules(limit int, search string) (map[string]RateLimitConf, int, error) {
	return r.mgr.ListRateLimitRules(limit, search)
}
