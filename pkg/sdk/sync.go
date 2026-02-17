package sdk

import "github.com/livp123/netxfw/internal/plugins/types"

// syncImpl implements SyncAPI interface.
// syncImpl 实现 SyncAPI 接口。
type syncImpl struct {
	mgr ManagerInterface
}

func (s *syncImpl) ToConfig(cfg *types.GlobalConfig) error {
	return s.mgr.SyncToFiles(cfg)
}

func (s *syncImpl) ToMap(cfg *types.GlobalConfig, overwrite bool) error {
	return s.mgr.SyncFromFiles(cfg, overwrite)
}

func (s *syncImpl) VerifyAndRepair(cfg *types.GlobalConfig) error {
	return s.mgr.VerifyAndRepair(cfg)
}
