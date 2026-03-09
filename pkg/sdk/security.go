package sdk

import "time"

// SecurityImpl implements SecurityAPI interface.
// SecurityImpl 实现 SecurityAPI 接口。
type SecurityImpl struct {
	mgr ManagerInterface
}

func (s *SecurityImpl) SetDefaultDeny(enable bool) error {
	return s.mgr.SetDefaultDeny(enable)
}

func (s *SecurityImpl) SetEnableAFXDP(enable bool) error {
	return s.mgr.SetEnableAFXDP(enable)
}

func (s *SecurityImpl) SetDropFragments(enable bool) error {
	return s.mgr.SetDropFragments(enable)
}

func (s *SecurityImpl) SetStrictTCP(enable bool) error {
	return s.mgr.SetStrictTCP(enable)
}

func (s *SecurityImpl) SetSYNLimit(enable bool) error {
	return s.mgr.SetSYNLimit(enable)
}

func (s *SecurityImpl) SetConntrack(enable bool) error {
	return s.mgr.SetConntrack(enable)
}

func (s *SecurityImpl) SetConntrackTimeout(timeout time.Duration) error {
	return s.mgr.SetConntrackTimeout(timeout)
}

func (s *SecurityImpl) SetBogonFilter(enable bool) error {
	return s.mgr.SetBogonFilter(enable)
}

func (s *SecurityImpl) SetAutoBlock(enable bool) error {
	return s.mgr.SetAutoBlock(enable)
}

func (s *SecurityImpl) SetAutoBlockExpiry(duration time.Duration) error {
	return s.mgr.SetAutoBlockExpiry(duration)
}
