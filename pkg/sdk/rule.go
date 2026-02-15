package sdk

// RuleAPI defines the interface for rule operations (IP/Port rules).
// RuleAPI 定义了规则操作（IP/端口规则）的接口。
type RuleAPI interface {
	// Add adds an IP/Port rule.
	// Add 添加一个 IP/端口规则。
	Add(cidr string, port uint16, action uint8) error

	// Remove removes an IP/Port rule.
	// Remove 移除一个 IP/端口规则。
	Remove(cidr string, port uint16) error

	// Clear removes all IP/Port rules.
	// Clear 移除所有 IP/端口规则。
	Clear() error

	// List returns a list of IP/Port rules.
	// List 返回 IP/端口规则的列表。
	List(isIPv6 bool, limit int, search string) ([]IPPortRule, int, error)

	// AddIPPortRule adds an IP/Port rule.
	// AddIPPortRule 添加一个 IP/端口规则。
	AddIPPortRule(cidr string, port uint16, action uint8) error

	// RemoveIPPortRule removes an IP/Port rule.
	// RemoveIPPortRule 移除一个 IP/端口规则。
	RemoveIPPortRule(cidr string, port uint16) error

	// ListIPPortRules returns a list of IP/Port rules.
	// ListIPPortRules 返回 IP/端口规则的列表。
	ListIPPortRules(limit int, search string) ([]IPPortRule, int, error)

	// AllowPort adds a port to the global allowed list.
	// AllowPort 将端口添加到全局允许列表。
	AllowPort(port uint16) error

	// RemoveAllowedPort removes a port from the global allowed list.
	// RemoveAllowedPort 从全局允许列表中移除端口。
	RemoveAllowedPort(port uint16) error

	// AddRateLimitRule adds a rate limit rule for an IP.
	// AddRateLimitRule 为 IP 添加限速规则。
	AddRateLimitRule(ip string, rate, burst uint64) error

	// RemoveRateLimitRule removes a rate limit rule for an IP.
	// RemoveRateLimitRule 移除 IP 的限速规则。
	RemoveRateLimitRule(ip string) error

	// ListRateLimitRules lists rate limit rules.
	// ListRateLimitRules 列出限速规则。
	ListRateLimitRules(limit int, search string) (map[string]RateLimitConf, int, error)
}

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
