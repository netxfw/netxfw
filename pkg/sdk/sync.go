package sdk

import "github.com/livp123/netxfw/internal/plugins/types"

// SyncAPI defines methods for synchronizing configuration.
// SyncAPI 定义了同步配置的方法。
type SyncAPI interface {
	// ToConfig dumps runtime BPF maps to configuration files.
	// ToConfig 将运行时 BPF Map 转储到配置文件。
	ToConfig(cfg *types.GlobalConfig) error

	// ToMap applies configuration files to runtime BPF maps.
	// ToMap 将配置文件应用到运行时 BPF Map。
	ToMap(cfg *types.GlobalConfig, overwrite bool) error

	// VerifyAndRepair verifies the consistency between config and maps.
	// VerifyAndRepair 验证配置和 Map 之间的一致性。
	VerifyAndRepair(cfg *types.GlobalConfig) error
}

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
