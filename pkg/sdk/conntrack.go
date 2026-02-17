package sdk

// conntrackImpl implements ConntrackAPI interface.
// conntrackImpl 实现 ConntrackAPI 接口。
type conntrackImpl struct {
	mgr ManagerInterface
}

func (c *conntrackImpl) List() ([]ConntrackEntry, error) {
	return c.mgr.ListAllConntrackEntries()
}

func (c *conntrackImpl) Count() (int, error) {
	return c.mgr.GetConntrackCount()
}
