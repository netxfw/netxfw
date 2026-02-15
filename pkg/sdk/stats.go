package sdk

// StatsAPI defines the interface for statistics operations.
// StatsAPI 定义了统计操作的接口。
type StatsAPI interface {
	// GetCounters returns global pass and drop counts.
	// GetCounters 返回全局放行和丢弃计数。
	GetCounters() (pass uint64, drop uint64, err error)

	// GetDropDetails returns detailed drop statistics.
	// GetDropDetails 返回详细的拦截统计信息。
	GetDropDetails() ([]DropDetailEntry, error)

	// GetPassDetails returns detailed pass statistics.
	// GetPassDetails 返回详细的放行统计信息。
	GetPassDetails() ([]DropDetailEntry, error)

	// GetLockedIPCount returns the number of currently locked IPs.
	// GetLockedIPCount 返回当前被锁定的 IP 数量。
	GetLockedIPCount() (int, error)
}

type statsImpl struct {
	mgr ManagerInterface
}

func (s *statsImpl) GetCounters() (uint64, uint64, error) {
	pass, err := s.mgr.GetPassCount()
	if err != nil {
		return 0, 0, err
	}
	drop, err := s.mgr.GetDropCount()
	if err != nil {
		return 0, 0, err
	}
	return pass, drop, nil
}

func (s *statsImpl) GetDropDetails() ([]DropDetailEntry, error) {
	return s.mgr.GetDropDetails()
}

func (s *statsImpl) GetPassDetails() ([]DropDetailEntry, error) {
	return s.mgr.GetPassDetails()
}

func (s *statsImpl) GetLockedIPCount() (int, error) {
	count, err := s.mgr.GetLockedIPCount()
	return int(count), err
}

// DropDetailEntry represents detailed statistics for dropped/passed packets.
// DropDetailEntry 代表拦截/放行数据包的详细统计信息。
// (Moved from api.go if not already there, but api.go has it. We rely on api.go definitions)
