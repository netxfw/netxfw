package sdk

// ConntrackImpl implements ConntrackAPI interface.
// ConntrackImpl 实现 ConntrackAPI 接口。
type ConntrackImpl struct {
	mgr ManagerInterface
}

func (c *ConntrackImpl) List() ([]ConntrackEntry, error) {
	return c.mgr.ListAllConntrackEntries()
}

func (c *ConntrackImpl) Count() (int, error) {
	return c.mgr.GetConntrackCount()
}
