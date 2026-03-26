package sdk

// SyncImpl implements SyncAPI interface.
// SyncImpl 实现 SyncAPI 接口。
type SyncImpl struct {
	mgr ManagerInterface
}

func (s *SyncImpl) ToConfig(cfg *GlobalConfig) error {
	return s.mgr.SyncToFiles(cfg)
}

func (s *SyncImpl) ToMap(cfg *GlobalConfig, overwrite bool) error {
	return s.mgr.SyncFromFiles(cfg, overwrite)
}

func (s *SyncImpl) VerifyAndRepair(cfg *GlobalConfig) error {
	return s.mgr.VerifyAndRepair(cfg)
}
