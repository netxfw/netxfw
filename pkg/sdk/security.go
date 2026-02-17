package sdk

import "time"

// SecurityAPI defines methods for security configuration.
// SecurityAPI 定义了安全配置的方法。
type SecurityAPI interface {
	SetDefaultDeny(enable bool) error
	SetEnableAFXDP(enable bool) error
	SetDropFragments(enable bool) error
	SetStrictTCP(enable bool) error
	SetSYNLimit(enable bool) error
	SetConntrack(enable bool) error
	SetConntrackTimeout(timeout time.Duration) error
	SetBogonFilter(enable bool) error
	SetAutoBlock(enable bool) error
	SetAutoBlockExpiry(duration time.Duration) error
}

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
