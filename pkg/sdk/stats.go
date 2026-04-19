package sdk

// StatsImpl implements StatsAPI interface.
// StatsImpl 实现 StatsAPI 接口。
type StatsImpl struct {
	mgr ManagerInterface
}

func (s *StatsImpl) GetCounters() (uint64, uint64, error) {
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

func (s *StatsImpl) GetDropDetails() ([]DropDetailEntry, error) {
	return s.mgr.GetDropDetails()
}

func (s *StatsImpl) GetPassDetails() ([]DropDetailEntry, error) {
	return s.mgr.GetPassDetails()
}

func (s *StatsImpl) GetLockedIPCount() (int, error) {
	count, err := s.mgr.GetLockedIPCount()
	return int(count), err
}

func (s *StatsImpl) GetDynamicLockedIPCount() (uint64, error) {
	return s.mgr.GetDynLockListCount()
}

func (s *StatsImpl) GetWhitelistCount() (int, error) {
	return s.mgr.GetWhitelistCount()
}

func (s *StatsImpl) GetConntrackCount() (int, error) {
	return s.mgr.GetConntrackCount()
}

func (s *StatsImpl) GetGlobalStats() (*GlobalStats, error) {
	return s.mgr.GetGlobalStats()
}
