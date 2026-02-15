package sdk

// WhitelistAPI defines the interface for whitelist operations.
// WhitelistAPI 定义了白名单操作的接口。
type WhitelistAPI interface {
	// Add adds an IP or CIDR to the whitelist.
	// Add 将 IP 或 CIDR 添加到白名单。
	// Optional port can be provided. If port > 0, it whitelists only that port.
	Add(cidr string, port uint16) error

	// AddWithPort adds an IP or CIDR to the whitelist for a specific port.
	// AddWithPort 将特定端口的 IP 或 CIDR 添加到白名单。
	AddWithPort(cidr string, port uint16) error

	// Remove removes an IP or CIDR from the whitelist.
	// Remove 从白名单中移除 IP 或 CIDR。
	Remove(cidr string) error

	// Clear removes all entries from the whitelist.
	// Clear 移除白名单中的所有条目。
	Clear() error

	// Contains checks if an IP is in the whitelist.
	// Contains 检查 IP 是否在白名单中。
	Contains(ip string) (bool, error)

	// List returns a list of whitelisted IPs.
	// List 返回白名单 IP 的列表。
	List(limit int, search string) ([]string, int, error)
}

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
