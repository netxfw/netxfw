package sdk

// statsImpl implements StatsAPI interface.
// statsImpl 实现 StatsAPI 接口。
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
