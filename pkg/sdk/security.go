package sdk

import "time"

// securityImpl implements SecurityAPI interface.
// securityImpl 实现 SecurityAPI 接口。
type securityImpl struct {
	mgr ManagerInterface
}

func (s *securityImpl) SetDefaultDeny(enable bool) error {
	return s.mgr.SetDefaultDeny(enable)
}

func (s *securityImpl) SetEnableAFXDP(enable bool) error {
	return s.mgr.SetEnableAFXDP(enable)
}

func (s *securityImpl) SetDropFragments(enable bool) error {
	return s.mgr.SetDropFragments(enable)
}

func (s *securityImpl) SetStrictTCP(enable bool) error {
	return s.mgr.SetStrictTCP(enable)
}

func (s *securityImpl) SetSYNLimit(enable bool) error {
	return s.mgr.SetSYNLimit(enable)
}

func (s *securityImpl) SetConntrack(enable bool) error {
	return s.mgr.SetConntrack(enable)
}

func (s *securityImpl) SetConntrackTimeout(timeout time.Duration) error {
	return s.mgr.SetConntrackTimeout(timeout)
}

func (s *securityImpl) SetBogonFilter(enable bool) error {
	return s.mgr.SetBogonFilter(enable)
}

func (s *securityImpl) SetAutoBlock(enable bool) error {
	return s.mgr.SetAutoBlock(enable)
}

func (s *securityImpl) SetAutoBlockExpiry(duration time.Duration) error {
	return s.mgr.SetAutoBlockExpiry(duration)
}
