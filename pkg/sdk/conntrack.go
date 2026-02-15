package sdk

// ConntrackAPI defines methods for connection tracking operations.
// ConntrackAPI 定义了连接跟踪操作的方法。
type ConntrackAPI interface {
	// List returns all active connections.
	// List 返回所有活动连接。
	List() ([]ConntrackEntry, error)

	// Count returns the number of active connections.
	// Count 返回活动连接的数量。
	Count() (int, error)
}

type conntrackImpl struct {
	mgr ManagerInterface
}

func (c *conntrackImpl) List() ([]ConntrackEntry, error) {
	return c.mgr.ListAllConntrackEntries()
}

func (c *conntrackImpl) Count() (int, error) {
	return c.mgr.GetConntrackCount()
}
