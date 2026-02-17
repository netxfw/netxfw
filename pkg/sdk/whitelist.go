package sdk

// whitelistImpl implements WhitelistAPI interface.
// whitelistImpl 实现 WhitelistAPI 接口。
type whitelistImpl struct {
	mgr ManagerInterface
}

func (w *whitelistImpl) Add(cidr string, port uint16) error {
	return w.mgr.AddWhitelistIP(cidr, port)
}

func (w *whitelistImpl) AddWithPort(cidr string, port uint16) error {
	return w.mgr.AddWhitelistIP(cidr, port)
}

func (w *whitelistImpl) Remove(cidr string) error {
	return w.mgr.RemoveWhitelistIP(cidr)
}

func (w *whitelistImpl) Clear() error {
	return w.mgr.ClearWhitelist()
}

func (w *whitelistImpl) Contains(ip string) (bool, error) {
	return w.mgr.IsIPInWhitelist(ip)
}

func (w *whitelistImpl) List(limit int, search string) ([]string, int, error) {
	return w.mgr.ListWhitelistIPs(limit, search)
}
