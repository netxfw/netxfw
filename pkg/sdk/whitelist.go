package sdk

// WhitelistImpl implements WhitelistAPI interface.
// WhitelistImpl 实现 WhitelistAPI 接口。
type WhitelistImpl struct {
	mgr ManagerInterface
}

func (w *WhitelistImpl) Add(cidr string, port uint16) error {
	return w.mgr.AddWhitelistIP(cidr, port)
}

func (w *WhitelistImpl) AddWithPort(cidr string, port uint16) error {
	return w.mgr.AddWhitelistIP(cidr, port)
}

func (w *WhitelistImpl) Remove(cidr string) error {
	return w.mgr.RemoveWhitelistIP(cidr)
}

func (w *WhitelistImpl) Clear() error {
	return w.mgr.ClearWhitelist()
}

func (w *WhitelistImpl) Contains(ip string) (bool, error) {
	return w.mgr.IsIPInWhitelist(ip)
}

func (w *WhitelistImpl) List(limit int, search string) ([]string, int, error) {
	return w.mgr.ListWhitelistIPs(limit, search)
}
