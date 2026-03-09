package sdk

import "github.com/netxfw/netxfw/internal/plugins/types"

// SyncImpl implements SyncAPI interface.
// SyncImpl 实现 SyncAPI 接口。
type SyncImpl struct {
	mgr ManagerInterface
}

func (s *SyncImpl) ToConfig(cfg *types.GlobalConfig) error {
	return s.mgr.SyncToFiles(cfg)
}

func (s *SyncImpl) ToMap(cfg *types.GlobalConfig, overwrite bool) error {
	return s.mgr.SyncFromFiles(cfg, overwrite)
}

func (s *SyncImpl) VerifyAndRepair(cfg *types.GlobalConfig) error {
	return s.mgr.VerifyAndRepair(cfg)
}
