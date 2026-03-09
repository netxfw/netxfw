package sdk

// RuleImpl implements RuleAPI interface.
// RuleImpl 实现 RuleAPI 接口。
type RuleImpl struct {
	mgr ManagerInterface
}

func (r *RuleImpl) Add(cidr string, port uint16, action uint8) error {
	return r.mgr.AddIPPortRule(cidr, port, action)
}

func (r *RuleImpl) Remove(cidr string, port uint16) error {
	return r.mgr.RemoveIPPortRule(cidr, port)
}

func (r *RuleImpl) Clear() error {
	return r.mgr.ClearIPPortRules()
}

func (r *RuleImpl) List(isIPv6 bool, limit int, search string) ([]IPPortRule, int, error) {
	return r.mgr.ListIPPortRules(isIPv6, limit, search)
}

func (r *RuleImpl) AddIPPortRule(cidr string, port uint16, action uint8) error {
	return r.mgr.AddIPPortRule(cidr, port, action)
}

func (r *RuleImpl) RemoveIPPortRule(cidr string, port uint16) error {
	return r.mgr.RemoveIPPortRule(cidr, port)
}

func (r *RuleImpl) ListIPPortRules(limit int, search string) ([]IPPortRule, int, error) {
	return r.mgr.ListIPPortRules(false, limit, search)
}

func (r *RuleImpl) AllowPort(port uint16) error {
	return r.mgr.AllowPort(port)
}

func (r *RuleImpl) RemoveAllowedPort(port uint16) error {
	return r.mgr.RemoveAllowedPort(port)
}

func (r *RuleImpl) AddRateLimitRule(ip string, rate, burst uint64) error {
	return r.mgr.AddRateLimitRule(ip, rate, burst)
}

func (r *RuleImpl) RemoveRateLimitRule(ip string) error {
	return r.mgr.RemoveRateLimitRule(ip)
}

func (r *RuleImpl) ListRateLimitRules(limit int, search string) (map[string]RateLimitConf, int, error) {
	return r.mgr.ListRateLimitRules(limit, search)
}
